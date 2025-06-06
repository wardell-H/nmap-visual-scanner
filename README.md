# Nmap 可视化扫描器（纯 Python 实现）

一个跨平台的图形化网络扫描工具，使用 Python 自行实现 Nmap 的核心功能，并通过 PyQt 提供用户友好的界面。无需依赖系统安装 Nmap，完全由 Python 实现扫描逻辑。

## 功能特色

- ✅ 主机发现（Ping / TCP Ping）
- ✅ 端口扫描（TCP / UDP）
- ✅ 简易服务识别（如 HTTP、FTP、SSH 等）
- ✅ 操作系统指纹识别
- ✅ 扫描结果实时展示
- ✅ 支持多线程 / 异步扫描加速
- ✅ 跨平台支持：Windows / Linux

## 技术栈

- Python 3.10
- PyQt5（图形界面）
- socket / scapy（实现网络协议）
- concurrent.futures（并发扫描任务调度）

## 快速开始

1. 克隆项目

```bash
git clone https://github.com/your-username/nmap-visual-scanner.git
cd nmap-visual-scanner
```
2. 安装依赖
```bash
pip install -r requirements.txt
```
3. 运行主程序

```bash
python main.py
```

## 许可证
本项目采用 MIT 协议，详见 LICENSE 文件。


## 项目结构
```
nmap-visual-scanner/
├── main.py                # 应用程序入口，加载 PyQt 主界面
├── README.md              # 项目说明
├── LICENSE                # MIT 许可证
├── requirements.txt       # 项目依赖
├── .gitignore             # Git 忽略文件

├── core/                  # 核心扫描功能（Nmap 功能的 Python 实现）
│   ├── discovery.py       # 主机发现（ICMP Ping, TCP Ping）
│   ├── port_scanner.py    # TCP/UDP 端口扫描
│   ├── service_probe.py   # 协议识别、Banner抓取
│   ├── os_fingerprint.py  # 操作系统识别（可选）
│   └── utils.py           # 公共工具函数（如 IP 处理、多线程等）

├── ui/                    # 图形界面模块（PyQt 界面）
│   ├── main_window.py     # 主窗口逻辑
│   ├── widgets.py         # 自定义控件（如结果展示表、日志区域等）
│   ├── icons/             # 图标文件夹（.ico / .png）
│   └── style/             # 样式文件（QSS 等）

├── data/                  # 运行时数据保存（扫描历史/缓存等）
│   └── scan_results.json

├── tests/                 # 单元测试
│   └── test_scanner.py
```


