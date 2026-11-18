import argparse
import socket
import random
import time
import gzip
from urllib.parse import urlparse, unquote
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.sessions import TCPSession
from scapy.sendrecv import sr1, send
from scapy.all import sniff, wrpcap


def resolve_hostname(hostname):
    """Разрешает доменное имя в IP-адрес."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Ошибка разрешения доменного имени '{hostname}': {e}")
        return None


def parse_url(url_arg):
    """Парсит URL и извлекает hostname, path и scheme."""
    if not url_arg.startswith('http://') and not url_arg.startswith('https://'):
        url_arg = 'http://' + url_arg
    
    try:
        parsed = urlparse(url_arg)
        hostname = parsed.hostname
        path = parsed.path if parsed.path else '/'
        scheme = parsed.scheme or 'http'
        return hostname, path, scheme
    except Exception as e:
        print(f"Ошибка парсинга URL: {e}")
        return None, None, None


def send_http_request(hostname, path, custom_request=None):
    """Отправляет HTTP-запрос через Scapy."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None
    
    port = 80
    client_sport = random.randint(1025, 65500)
    
    # Формируем HTTP-запрос
    if custom_request:
        http_request_str = custom_request
    else:
        http_request_str = f'GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n'
    
    # Устанавливаем TCP-соединение
    syn = IP(dst=dest_ip) / TCP(sport=client_sport, dport=port, flags='S')
    syn_ack = sr1(syn, timeout=5, verbose=False)
    
    if not syn_ack or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 0x12:
        print(f"Не удалось установить соединение с {hostname}")
        return None
    
    # Отправляем ACK
    client_seq = syn_ack[TCP].ack
    client_ack = syn_ack[TCP].seq + 1
    ack_packet = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='A'
    )
    send(ack_packet, verbose=False)
    
    time.sleep(0.1)
    
    # Отправляем HTTP-запрос
    http_request = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='PA'
    ) / http_request_str
    
    send(http_request, verbose=False)
    
    return dest_ip, port, client_sport


def capture_traffic(hostname, timeout=30, output_file=None):
    """Перехватывает HTTP-трафик для указанного хоста."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None
    
    print(f"Начало перехвата трафика для {hostname} ({dest_ip})...")
    
    packets = sniff(
        filter=f"tcp port 80 and host {dest_ip}",
        timeout=timeout,
        session=TCPSession
    )
    
    print(f"Перехвачено пакетов: {len(packets)}")
    
    if output_file and packets:
        wrpcap(output_file, packets)
        print(f"Трафик сохранен в {output_file}")
    
    return packets


def analyze_packets(packets):
    if not packets:
        print("Нет пакетов для анализа")
        return

    sigs = ['<script>', 'onerror=', 'alert(', '<img']

    for pkt in packets:
        # Встроенный слой HTTP-запроса
        if pkt.haslayer(HTTPRequest):
            req = pkt[HTTPRequest]
            method = req.Method.decode(errors='ignore')
            raw_path = req.Path.decode(errors='ignore')
            path = unquote(raw_path)
            host = req.Host.decode(errors='ignore') if req.Host else ''
            body = unquote(bytes(req.payload).decode(errors='ignore'))

            if any(s in path.lower() or s in body.lower() for s in sigs):
                print(f"[ЗАПРОС С XSS] {method} {path}")
                print(f"  Host: {host} | Сырой HTTP-путь: {raw_path}")
                if body:
                    print(f"  POST-данные: {body}")

        # Встроенный слой HTTP-ответа
        elif pkt.haslayer(HTTPResponse):
            resp = pkt[HTTPResponse]
            status = resp.Status_Code.decode(errors='ignore')
            encoding = resp.Content_Encoding.decode(errors='ignore') if resp.Content_Encoding else 'none'
            raw_body = bytes(resp.payload)
            
            # Если Scapy оставил ответ сжатым в gzip — распаковываем
            if raw_body.startswith(b'\x1f\x8b'):
                try:
                    raw_body = gzip.decompress(raw_body)
                except Exception:
                    pass 

            html = raw_body.decode(errors='ignore')
            print(f"[ОТВЕТ] Статус: {status} | Encoding: {encoding} | Размер HTML: {len(html)} байт")

            for s in sigs:
                pos = html.lower().find(s)
                if pos != -1:
                    print(f"  [!] XSS В ОТВЕТЕ: ...{html[pos-40:pos+80].strip()}...\n")
                    break


def analyze_saved_traffic(pcap_file):
    """Анализирует сохраненный трафик из .pcap файла."""
    print(f"Анализ трафика из файла: {pcap_file}")
    packets = sniff(offline=pcap_file, session=TCPSession)
    analyze_packets(packets)


def main():
    parser = argparse.ArgumentParser(
        description='Анализ XSS-уязвимостей с использованием Scapy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
            Примеры использования:
            # Отправка HTTP-запроса
            python scapy_xss_analyzer.py --send google-gruyere.appspot.com/XXXXX
            
            # Перехват трафика
            python scapy_xss_analyzer.py --capture google-gruyere.appspot.com --timeout 60 --output traffic.pcap
            
            # Анализ сохраненного трафика
            python scapy_xss_analyzer.py --analyze traffic.pcap
        """
    )
    
    parser.add_argument(
        '--send',
        metavar='URL',
        help='Отправить HTTP-запрос на указанный URL'
    )
    
    parser.add_argument(
        '--capture',
        metavar='HOSTNAME',
        help='Перехватить трафик для указанного хоста'
    )
    
    parser.add_argument(
        '--analyze',
        metavar='PCAP_FILE',
        help='Проанализировать сохраненный трафик из .pcap файла'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Таймаут для перехвата трафика в секундах (по умолчанию: 30)'
    )
    
    parser.add_argument(
        '--output',
        metavar='FILE',
        help='Имя файла для сохранения перехваченного трафика'
    )
    
    parser.add_argument(
        '--request',
        metavar='HTTP_REQUEST',
        help='Кастомный HTTP-запрос (для этапа 3)'
    )
    
    args = parser.parse_args()
    
    # Проверка аргументов
    if not any([args.send, args.capture, args.analyze]):
        parser.print_help()
        return
    
    # Отправка HTTP-запроса
    if args.send:
        hostname, path, scheme = parse_url(args.send)
        if not hostname:
            print("Ошибка: не удалось распарсить URL")
            return
        
        print(f"Отправка HTTP-запроса на {hostname}{path}")
        result = send_http_request(hostname, path, args.request)
        if result:
            print("HTTP-запрос отправлен")
        else:
            print("Ошибка при отправке HTTP-запроса")
    
    # Перехват трафика|
    if args.capture:
        packets = capture_traffic(args.capture, args.timeout, args.output)
        if packets:
            analyze_packets(packets)
    
    # Анализ сохраненного трафика
    if args.analyze:
        analyze_saved_traffic(args.analyze)


if __name__ == '__main__':
    main()
