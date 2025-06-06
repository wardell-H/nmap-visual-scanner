from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QToolBar, QAction,
    QLabel, QPushButton, QTextEdit, QLineEdit, QTabWidget, QComboBox, QGroupBox,QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont
import os
import json
import sys
import ipaddress
import networkx as nx
from core.discovery import scan_subnet
from core.port_scanner import scan_port
from core.os_fingerprint import os_fingerprint
from core.service_probe import guess_service
from functools import partial

def resource_path(relative_path):
    """获取资源的绝对路径，兼容开发和打包环境"""
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

def get_runtime_data_path(relative_path):
    """返回一个可用于写入文件的路径，适配打包后环境"""
    if getattr(sys, 'frozen', False):
        # PyInstaller 打包后的路径：可写的目录
        base_path = os.path.dirname(sys.executable)
    else:
        # 普通运行时：当前目录
        base_path = os.path.abspath(".")

    full_path = os.path.join(base_path, relative_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    return full_path

history_path = get_runtime_data_path("data/scan_results.json")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        # 初始化扫描历史
        self.scan_history = []

        # 加载历史记录
        self.load_scan_history()

        # 初始化扫描结果
        self.latest_scan_results = []
        self.setWindowTitle("Nmap 可视化扫描器")
        self.setMinimumSize(1000, 700)
        self.load_stylesheet(resource_path("./ui/style/mac_light.qss"))
        # self.load_stylesheet("./ui/style/vscode_dark.qss")
        self.current_theme = "mac"
        self.setup_toolbar()

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)

        input_group = QGroupBox("扫描设置")
        input_layout = QHBoxLayout()

        label_target = QLabel("目标地址：")
        input_layout.addWidget(label_target)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("例如：192.168.1.0/24")
        input_layout.addWidget(self.target_input)

        label_profile = QLabel("扫描配置：")
        input_layout.addWidget(label_profile)

        self.profile_box = QComboBox()
        self.profile_box.addItems(["端口扫描", "快速扫描", "主机扫描"])
        input_layout.addWidget(self.profile_box)

        self.scan_button = QPushButton("开始扫描")
        input_layout.addWidget(self.scan_button)

        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)

        command_layout = QHBoxLayout()
        label_cmd = QLabel("生成命令：")
        command_layout.addWidget(label_cmd)

        self.command_line = QLineEdit("")
        self.command_line.setReadOnly(True)
        self.command_line.setFont(QFont("Courier New", 10))
        self.command_line.setStyleSheet("background-color: #f4f4f4;")
        command_layout.addWidget(self.command_line)

        main_layout.addLayout(command_layout)

        self.tab_widget = QTabWidget()
        self.output_tabs = {}

        tab_names = {
            "Nmap Output": "扫描输出",
            "Ports / Hosts": "端口与服务",
            "Topology": "拓扑结构",
            "Host Details": "主机详情",
            "Scan History": "扫描历史", 
        }

        for key, name in tab_names.items():
            tab = QWidget()
            layout = QVBoxLayout()

            if key == "Topology":
                from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
                from matplotlib.figure import Figure

                self.topology_figure = Figure()
                self.topology_canvas = FigureCanvas(self.topology_figure)
                layout.addWidget(self.topology_canvas)
            else:
                text_edit = QTextEdit()
                text_edit.setReadOnly(True)
                text_edit.setFont(QFont("Consolas", 10))
                text_edit.setStyleSheet("background-color: #ffffff; border: 1px solid #ccc;")
                layout.addWidget(text_edit)
                self.output_tabs[key] = text_edit

            tab.setLayout(layout)
            self.tab_widget.addTab(tab, name)
            # self.output_tabs[key] = text_edit

        main_layout.addWidget(self.tab_widget)

        # ✅ 绑定标签页切换事件
        self.tab_widget.currentChanged.connect(self.on_tab_changed)

        # ===== 绑定按钮事件 =====
        self.scan_button.clicked.connect(self.on_scan_clicked)

        # 保存最新扫描结果（用于主机详情）
        self.latest_scan_results = []

    def save_scan_history(self):
        # 保存扫描历史到 scan_results.json 文件
        try:
            with open(history_path, "w", encoding="utf-8") as f:
                json.dump(self.scan_history, f, ensure_ascii=False, indent=4)
        except Exception as e:
            print(f"保存扫描历史时发生错误: {e}")

    def load_scan_history(self):
        # 加载扫描历史记录从 scan_results.json 文件
        if os.path.exists(history_path):
            try:
                with open(history_path, "r", encoding="utf-8") as f:
                    self.scan_history = json.load(f)
            except Exception as e:
                print(f"加载扫描历史时发生错误: {e}")

    def display_scan_history(self):
        text_edit = self.output_tabs["Scan History"]
        text_edit.clear()

        text_edit.append('<span style="font-size:16px; font-weight:bold; color:#2e86de;">✅ 扫描历史记录：</span><br>')

        if not self.scan_history:
            text_edit.append('<span style="color:gray;">🔹 当前没有扫描记录。</span>')
            return

        for idx, history in enumerate(self.scan_history, start=1):
            results = history.get("results", [])

            # 过滤掉没有内容的历史
            filtered_results = []
            for res in results:
                scan_type = res.get("scan_type", "unknown")
                if scan_type == "port" and not res.get("open_ports"):  # 跳过无开放端口
                    continue
                filtered_results.append(res)

            if not filtered_results:
                continue  # 整条记录没有需要展示的内容，就跳过

            text_edit.append(f"<b>🔸 扫描 {idx}</b><br>")
            for res in filtered_results:
                ip = res.get("ip", "未知IP")
                scan_type = res.get("scan_type", "unknown")

                if scan_type == "port":
                    ports = ", ".join(map(str, res.get("open_ports", [])))
                    result_text = f"<span style='color:#27ae60;'>{ports}</span>"
                elif scan_type == "host":
                    status = res.get("status", "未知状态")
                    result_text = f"<span style='color:#e67e22;'>{status}</span>"
                else:
                    result_text = "<span style='color:gray;'>未知结果</span>"

                entry = (
                    f"<span style='color:#2980b9;'>IP</span>: {ip} | "
                    f"<span style='color:#2980b9;'>类型</span>: {scan_type} | "
                    f"<span style='color:#2980b9;'>结果</span>: {result_text}<br>"
                )
                text_edit.append(entry)

            text_edit.append("<br>")


    def handle_scan_result(self, results):
        if not results or not isinstance(results, list):
            print("⚠️ 无效扫描结果")
            return

        new_results = []
        for res in results:
            scan_type = "port" if "open_ports" in res else "host" if "status" in res else "unknown"
            new_result = {
                "ip": res.get("ip", "unknown"),
                "scan_type": scan_type,
            }

            if scan_type == "port":
                new_result["open_ports"] = res.get("open_ports", [])
            elif scan_type == "host":
                new_result["status"] = res.get("status", "未知状态")

            new_results.append(new_result)

        scan_record = {
            "results": new_results
        }

        self.scan_history.append(scan_record)
        self.save_scan_history()

        # 保存扫描历史到文件


    def setup_toolbar(self):
        toolbar = QToolBar("工具栏")
        toolbar.setMovable(False)
        self.addToolBar(Qt.TopToolBarArea, toolbar)

        new_action = QAction("🆕 新建窗口", self)
        new_action.triggered.connect(self.create_new_window)
        toolbar.addAction(new_action)

        theme_action = QAction("🎨 切换主题", self)
        theme_action.triggered.connect(self.toggle_theme)
        toolbar.addAction(theme_action)

    # def draw_topology_graph(self):
    #     if not hasattr(self, "topology_figure"):
    #         return

    #     self.topology_figure.clear()
    #     ax = self.topology_figure.add_subplot(111)

    #     G = nx.Graph()
    #     G.add_node("localhost")

    #     for item in self.latest_scan_results:
    #         if item.get("status") == "UP":
    #             ip = item.get("ip")
    #             G.add_node(ip)
    #             G.add_edge("localhost", ip)

    #     pos = nx.spring_layout(G)
    #     nx.draw(G, pos, ax=ax, with_labels=True, node_color="skyblue", edge_color="gray", node_size=1200, font_size=10)
    #     self.topology_canvas.draw()
    def draw_topology_graph(self):
        if not hasattr(self, "topology_figure"):
            return

        self.topology_figure.clear()
        ax = self.topology_figure.add_subplot(111)

        G = nx.Graph()
        G.add_node("localhost")

        for item in self.latest_scan_results:
            ip = item.get("ip")
            # 主机扫描模式，判断是否是 "UP"
            if item.get("status") == "UP":
                G.add_node(ip)
                G.add_edge("localhost", ip)
            # 端口扫描模式，判断是否有开放端口
            elif "open_ports" in item and item["open_ports"]:
                G.add_node(ip)
                G.add_edge("localhost", ip)

        pos = nx.spring_layout(G)
        nx.draw(
            G, pos, ax=ax,
            with_labels=True,
            node_color="skyblue",
            edge_color="gray",
            node_size=1200,
            font_size=10
        )
        self.topology_canvas.draw()

    def create_new_window(self):
        new_win = MainWindow()
        new_win.show()
        if not hasattr(self, 'open_windows'):
            self.open_windows = []
        self.open_windows.append(new_win)

    def toggle_theme(self):
        if self.current_theme == "vscode":
            self.load_stylesheet(resource_path("./ui/style/mac_light.qss"))
            # self.load_stylesheet("./ui/style/mac_light.qss")
            self.current_theme = "mac"
        else:
            self.load_stylesheet(resource_path("./ui/style/vscode_dark.qss"))
            # self.load_stylesheet("./ui/style/vscode_dark.qss")
            self.current_theme = "vscode"

    def load_stylesheet(self, path):
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                self.setStyleSheet(f.read())
        else:
            print(f"⚠️ 样式文件未找到：{path}")

    def on_scan_clicked(self):
        target = self.target_input.text().strip()
        profile = self.profile_box.currentText()

        if not target:
            self.output_tabs["Nmap Output"].append("❗ 请先输入要扫描的目标地址。")
            return

        self.command_line.setText(f"正在扫描：{target}，配置：{profile}")
        self.output_tabs["Nmap Output"].append(f"📡 正在扫描目标：{target}，配置：{profile}")

        if profile == "主机扫描":
            self.thread = ScanThread(target, scan_type="host")
            self.thread.result_signal.connect(self.display_ping_results)
            self.thread.result_signal.connect(partial(self.on_scan_finished, scan_type="host"))
        elif profile == "端口扫描":
            self.thread = ScanThread(target, scan_type="port")
            self.thread.result_signal.connect(self.display_port_results)
            self.thread.result_signal.connect(partial(self.on_scan_finished, scan_type="port"))
        else:
            self.thread = ScanThread(target, scan_type="quick", scan_ports="80,443")
            self.thread.result_signal.connect(self.display_port_results)
            self.thread.result_signal.connect(partial(self.on_scan_finished, scan_type="port"))

        self.thread.start()

    def on_scan_finished(self, results, scan_type):
    # 标记每条记录的扫描类型
        for item in results:
            item["scan_type"] = scan_type

        self.latest_scan_results = results
        self.handle_scan_result(results)

        # 分类型展示
        if scan_type == "host":
            self.display_ping_results(results)
        elif scan_type == "port":
            self.display_port_results(results)
        elif scan_type == "service":
            self.display_service_results(results)

    def display_ping_results(self, results):
        self.latest_scan_results = results
        self.output_tabs["Nmap Output"].append("✅ 扫描完成，结果如下：\n")
        for item in results:
            if item['status'] == 'UP':
                line = f"{item['ip']} - 🟢在线"
                if item.get("hostname"):
                    line += f" ({item['hostname']})"
                self.output_tabs["Nmap Output"].append(line)

    def display_port_results(self, results):
        self.latest_scan_results = results
        self.output_tabs["Nmap Output"].append("✅ 扫描完成，结果如下：\n")
        for item in results:
            if "open_ports" in item and item["open_ports"]:
                line = f"{item['ip']} - 🟢在线, 开放端口: {', '.join(map(str, item['open_ports']))}"
            else:
                line = f"{item['ip']} - 🔴离线 或 无开放端口"
            if item.get("hostname"):
                line += f" ({item['hostname']})"
            self.output_tabs["Nmap Output"].append(line)
    # 展示端口与服务的结果
    def display_service_results(self, results):
        self.latest_scan_results = results
        self.output_tabs["Ports / Hosts"].clear()
        self.output_tabs["Ports / Hosts"].append("✅ 扫描完成，结果如下：\n")

        # 遍历每个扫描结果
        for item in results:
            ip = item.get("ip", "未知IP")
            open_ports = item.get("open_ports", [])

            if open_ports:
                self.output_tabs["Ports / Hosts"].append(f"🔹 {ip} - 开放端口与服务：")
                
                # 如果 open_ports 只是端口号列表，则直接迭代端口号
                for port in open_ports:
                    # 使用 guess_service 函数获取服务名称
                    service = guess_service(port)
                    
                    # 更加可视化地输出端口和服务对应关系
                    line = f"    🌐 端口 {port} → {service}"
                    self.output_tabs["Ports / Hosts"].append(line)
                
                self.output_tabs["Ports / Hosts"].append("")  # 空行分隔不同的IP

    def on_tab_changed(self, index):
        line = ""
        tab_name = self.tab_widget.tabText(index)
        if tab_name == "主机详情":
            self.output_tabs["Host Details"].clear()
            if not self.latest_scan_results:
                self.output_tabs["Host Details"].setText('<span style="color:gray;">尚无扫描结果。</span>')
                return

            for item in self.latest_scan_results:
                ip = item.get("ip", "未知IP")
                show_os = False

                # 主机扫描结果
                if item.get("status") == "UP":
                    show_os = True
                # 端口扫描结果，且有开放端口
                elif "open_ports" in item and item["open_ports"]:
                    show_os = True

                if show_os:
                    try:
                        os_result = os_fingerprint(ip)
                        line = (
                            f"<span style='color:#27ae60;'>🟢</span> "
                            f"<b>{ip}</b> - <span style='color:#2980b9;'>识别到操作系统：</span> "
                            f"<span style='color:#27ae60; font-weight:bold;'>{os_result}</span><br><br>"
                        )
                    except Exception as e:
                        line = (
                            f"<span style='color:#f39c12;'>🟡</span> "
                            f"<b>{ip}</b> - <span style='color:#e74c3c;'>操作系统识别失败：</span> "
                            f"<span style='color:gray;'>{str(e)}</span><br><br>"
                        )
                    self.output_tabs["Host Details"].append(line)
        elif tab_name == "拓扑结构":
            self.draw_topology_graph()
        elif tab_name == "端口与服务":
            self.display_service_results(self.latest_scan_results)
        elif tab_name == "扫描历史":
            self.display_scan_history() 


class ScanThread(QThread):
    result_signal = pyqtSignal(list)

    def __init__(self, target, scan_type="port", scan_ports=None):
        super().__init__()
        self.target = target
        self.scan_type = scan_type
        self.scan_ports = scan_ports

    def run(self):
        if self.scan_type == "host":
            results = scan_subnet(self.target)
        elif self.scan_type == "port":
            results = scan_port(self.target)
        elif self.scan_type == "quick":
            ports = [80, 443]
            results = scan_port(self.target, ports=ports)
        self.result_signal.emit(results)
