import socket
from concurrent.futures import ThreadPoolExecutor
from core.utils import concurrent_port_scan,normalize_subnet
def scan_ports_for_ip(ip, ports=range(1, 1025), timeout=1.0):
    open_ports = []

    def scan_single_port(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                return port
        return None

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_single_port, port) for port in ports]
        for future in futures:
            port = future.result()
            if port is not None:
                open_ports.append(port)

    return open_ports


def scan_port(subnet_prefix: str, ports=range(1, 1025), timeout=1.0):
    ip_list = normalize_subnet(subnet_prefix)

    def scan_func(ip):
        # print(f"🔍 正在扫描 {ip} ...")
        return scan_ports_for_ip(ip, ports=ports, timeout=timeout)

    return concurrent_port_scan(ip_list, scan_func)