"""TCP connect 포트 스캐너

"""
import argparse
import socket
import time
from concurrent.futures import ThreadPoolExecutor

# getservbyport가 모르는 포트를 위한 보조 딕셔너리
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 6379: "redis", 8080: "http-alt",
}


def scan_port(host, port, timeout):
    # 포트 하나에 TCP 연결을 시도. 열려 있으면 True.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        # connect_ex는 예외 대신 에러 코드를 반환한다. 0이면 연결 성공(OPEN)
        return sock.connect_ex((host, port)) == 0


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return COMMON_SERVICES.get(port, "unknown")


def parse_ports(text):
    # '80' 또는 '1-1000' 형태를 range로 변환.
    if "-" in text:
        start, end = map(int, text.split("-", 1))
    else:
        start = end = int(text)
    if not (1 <= start <= end <= 65535):
        raise argparse.ArgumentTypeError("포트는 1-65535 범위여야 합니다")
    return range(start, end + 1)


def main():
    parser = argparse.ArgumentParser(description="Simple TCP port scanner")
    parser.add_argument("--host", help="대상 IP 또는 도메인")
    parser.add_argument("--ports", type=parse_ports, help="포트 범위 (예: 1-1000)")
    parser.add_argument("--threads", type=int, default=50, help="동시 스레드 수 (1이면 순차 스캔)")
    parser.add_argument("--timeout", type=float, default=1.0, help="포트당 타임아웃(초)")
    args = parser.parse_args()

    # Level 1: 인자가 없으면 직접 입력받는다
    host = args.host or input("Target host: ").strip()
    ports = args.ports or parse_ports(input("Port range (e.g. 1-100): ").strip())

    try:
        ip = socket.gethostbyname(host)  # 도메인이면 IP로 변환
    except socket.gaierror:
        print(f"Cannot resolve host: {host}")
        return

    mode = "sequentially" if args.threads == 1 else f"with {args.threads} threads"
    print(f"Scanning {host} ({ip}) ports {ports.start}-{ports.stop - 1} {mode}...")

    start = time.time()
    if args.threads == 1:
        results = [scan_port(ip, p, args.timeout) for p in ports]
    else:
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            results = list(pool.map(lambda p: scan_port(ip, p, args.timeout), ports))
    elapsed = time.time() - start

    open_ports = [p for p, is_open in zip(ports, results) if is_open]
    for p in open_ports:
        print(f"Port {p} ({service_name(p)}): OPEN")

    print(f"Scan finished in {elapsed:.2f}s (open: {len(open_ports)}, closed: {len(ports) - len(open_ports)})")


if __name__ == "__main__":
    main()
