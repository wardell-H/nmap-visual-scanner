import scapy.all as scapy
import logging
from typing import Dict
from functools import lru_cache
# 设置日志记录
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 定义操作系统指纹的常见TTL值和窗口大小
OS_FINGERPRINTS = {
    "Windows": {"TTL": (128, 255), "Window": (8192, 65535)},
    "Linux": {"TTL": (64, 128), "Window": (5840, 64240)},
    "Mac OS": {"TTL": (64, 128), "Window": (8192, 65535)},
    "Router/Cisco": {"TTL": (255, 255), "Window": (2048, 4096)},
}

def guess_initial_ttl(ttl):
    for likely in [32, 64, 128, 255]:
        if ttl <= likely:
            return likely
    return ttl

@lru_cache(maxsize=128)
def os_fingerprint(ip: str) -> str:
    try:
        for port in [22, 80, 443, 8000]:
            syn_packet = scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="S")
            response = scapy.sr1(syn_packet, timeout=1, verbose=0)

            if response and response.haslayer(scapy.TCP):
                ttl = response.ttl
                window = response[scapy.TCP].window
                flags = response[scapy.TCP].flags
                logger.debug(f"收到响应: TTL={ttl} Window={window} Flags={flags}")

                init_ttl = guess_initial_ttl(ttl)

                for os_name, params in OS_FINGERPRINTS.items():
                    ttl_min, ttl_max = params["TTL"]
                    win_min, win_max = params["Window"]
                    if ttl_min <= init_ttl <= ttl_max and win_min <= window <= win_max:
                        return os_name
        return "未知操作系统"
    except Exception as e:
        logger.error(f"探测失败: {str(e)}", exc_info=True)
        return "错误"
