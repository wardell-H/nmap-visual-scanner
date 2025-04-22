import socket
import platform
import subprocess
from scapy.all import IP, ICMP, sr1, TCP
from typing import List
from core.utils import concurrent_scan,normalize_subnet

def is_alive_icmp(ip: str, timeout: float = 1.0) -> bool:
    """使用 ICMP 判断主机是否存活（需要管理员权限）"""
    try:
        pkt = IP(dst=ip)/ICMP()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        return resp is not None
    except PermissionError:
        print("⚠️ ICMP 扫描需要管理员权限！")
        return False


def is_alive_tcp(ip: str, ports: List[int] = [80, 443, 22, 3389], timeout: float = 1.0) -> bool:
    """使用 TCP Ping 判断主机是否存活"""
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:  # 连接成功
                return True
        except socket.error:
            continue
    return False


def ping_cross_platform(ip: str) -> bool:
    """使用系统 ping 命令（跨平台，备用方案）"""
    try:
        count_flag = "-n" if platform.system().lower() == "windows" else "-c"
        output = subprocess.run(
            ["ping", count_flag, "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return output.returncode == 0
    except Exception:
        return False




def scan_subnet(subnet_prefix: str, method: str = "icmp", timeout: float = 1.0, max_workers: int = 100) -> List[str]:
    """
    并发扫描子网内的活动主机。
    subnet_prefix: 例如 "192.168.1"
    method: icmp / tcp / ping
    """
    # ip_list = [f"{subnet_prefix}.{i}" for i in range(1, 255)]
    ip_list = normalize_subnet(subnet_prefix)
    if not ip_list:
        raise ValueError(f"无效的子网前缀：{subnet_prefix}")
    if method == "icmp":
        check_func = lambda ip: is_alive_icmp(ip, timeout)
    elif method == "tcp":
        check_func = lambda ip: is_alive_tcp(ip, timeout=timeout)
    elif method == "ping":
        check_func = ping_cross_platform
    else:
        raise ValueError(f"未知扫描方法：{method}")

    print(f"开始使用 {method.upper()} 并发扫描 {subnet_prefix}.1 - {subnet_prefix}.254")
    return concurrent_scan(ip_list, check_func, max_workers=max_workers)