from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Dict


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