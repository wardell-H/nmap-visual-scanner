COMMON_PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP (SSL)",
    993: "IMAP (SSL)",
    995: "POP3 (SSL)",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Proxy",
}

def guess_service(port):
    return COMMON_PORT_SERVICES.get(port, "未知服务")