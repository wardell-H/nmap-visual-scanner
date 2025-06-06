from core.discovery import scan_subnet
from core.port_scanner import scan_port
import ipaddress
from typing import Callable, List, Dict
from core.os_fingerprint import os_fingerprint
# scan_results = scan_subnet("100.80.179", method="icmp")  # 使用 ICMP
# # scan_subnet("100.80.179", method="tcp")   # 使用 TCP Ping（默认端口）
# # scan_subnet("100.80.179", method="ping")  # 使用系统 ping 命令
# for result in scan_results:
#     print(f"IP: {result['ip']} 状态: {result['status']}")

# def normalize_subnet(subnet: str) -> List[str]:
#     """
#     规范化 CIDR 格式子网，返回该子网内的所有 IP 地址。
#     :param subnet: CIDR 格式的子网，如 "100.80.179.0/24"
#     :return: 包含所有 IP 地址的列表
#     """
#     try:
#         # 使用 ipaddress 模块解析 CIDR 子网
#         network = ipaddress.IPv4Network(subnet, strict=False)
#         # 返回子网中的所有 IP 地址
#         return [str(ip) for ip in network.hosts()]  # network.hosts() 会排除网络地址和广播地址
#     except ValueError:
#         raise ValueError(f"无效的子网格式: {subnet}")

# # 示例用法
# subnet = "100.80.179.0/24"
# ip_list = normalize_subnet(subnet)
# print(ip_list)


# subnet = "100.80.179.0/24"
# result = scan_port(subnet)
# for entry in result:
#     print(f"{entry['ip']} 开放端口: {entry['open_ports']}")


ip = "127.0.0.1"  # 这里指定要识别的目标 IP
result = os_fingerprint(ip)
print(f"操作系统识别结果: {result}")