# Nmap 可视化扫描器（纯 Python 实现）

一个跨平台的图形化网络扫描工具，使用 Python 自行实现 Nmap 的核心功能，并通过 PyQt 提供用户友好的界面。无需依赖系统安装 Nmap，完全由 Python 实现扫描逻辑。

## 功能特色

- ✅ 主机发现（Ping / TCP Ping）
- ✅ 端口扫描（TCP / UDP）
- ✅ 简易服务识别（如 HTTP、FTP、SSH 等）
- ✅ （可选）操作系统指纹识别
- ✅ 扫描结果实时展示、自动化更新界面
- ✅ 支持多线程 / 异步扫描加速
- ✅ 跨平台支持：Windows / Linux

## 技术栈

- Python 3.8+
- PyQt5（图形界面）
- socket / scapy（实现网络协议）
- threading / asyncio（提升扫描性能）

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

许可证
本项目采用 MIT 协议，详见 LICENSE 文件。