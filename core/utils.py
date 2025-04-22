from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Dict
import ipaddress
import sys
import os

def resource_path(relative_path):
    """获取打包后的资源路径"""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def normalize_subnet(subnet: str) -> List[str]:
    """
    规范化 CIDR 格式子网，返回该子网内的所有 IP 地址。
    :param subnet: CIDR 格式的子网，如 "100.80.179.0/24"
    :return: 包含所有 IP 地址的列表
    """
    try:
        # 使用 ipaddress 模块解析 CIDR 子网
        network = ipaddress.IPv4Network(subnet, strict=False)
        # 返回子网中的所有 IP 地址
        return [str(ip) for ip in network.hosts()]  # network.hosts() 会排除网络地址和广播地址
    except ValueError:
        raise ValueError(f"无效的子网格式: {subnet}")

def concurrent_scan(
    ip_list: List[str],
    check_func: Callable[[str], bool],
    max_workers: int = 100
) -> List[Dict[str, str]]:
    """
    并发扫描 IP 列表，返回存活的主机及其扫描结果。
    :param ip_list: 要扫描的 IP 地址列表
    :param check_func: 判断主机是否存活的函数（参数是 IP，返回 bool）
    :param max_workers: 最大线程数
    :return: 包含主机 IP 和扫描结果的字典列表
    """
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(check_func, ip): ip for ip in ip_list}

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            result = {"ip": ip, "status": "DOWN"}

            try:
                if future.result():
                    result["status"] = "UP"
            except Exception as e:
                result["status"] = f"Error: {e}"

            results.append(result)

    return results


def concurrent_port_scan(
    ip_list: List[str],
    scan_func: Callable[[str], List[int]],
    max_workers: int = 100
) -> List[Dict[str, object]]:
    """
    并发对多个 IP 扫描端口，返回每台主机的开放端口列表。

    参数:
        ip_list: 要扫描的 IP 地址列表
        scan_func: 实际扫描函数，输入是 IP，返回开放端口列表
        max_workers: 最大并发线程数

    返回:
        List[dict]，如:
            [
                {"ip": "192.168.1.1", "open_ports": [22, 80]},
                {"ip": "192.168.1.2", "open_ports": []}
            ]
    """
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(scan_func, ip): ip for ip in ip_list}

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                ports = future.result()
                results.append({
                    "ip": ip,
                    "open_ports": ports
                })
            except Exception as e:
                results.append({
                    "ip": ip,
                    "open_ports": [],
                    "error": str(e)
                })

    return results