from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QToolBar, QAction,
    QLabel, QPushButton, QTextEdit, QLineEdit, QTabWidget, QComboBox, QGroupBox
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont
import os
import ipaddress
from core.discovery import scan_subnet
from core.port_scanner import scan_port
from core.os_fingerprint import os_fingerprint

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Nmap 可视化扫描器")
        self.setMinimumSize(1000, 700)
        self.load_stylesheet("./ui/style/mac_light.qss")
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

        self.command_line = QLineEdit("nmap -T4 -A -v")
        self.command_line.setReadOnly(True)
        self.command_line.setFont(QFont("Courier New", 10))
        self.command_line.setStyleSheet("background-color: #f4f4f4;")
        command_layout.addWidget(self.command_line)

        main_layout.addLayout(command_layout)

        self.tab_widget = QTabWidget()
        self.output_tabs = {}

        tab_names = {
            "Nmap Output": "扫描输出",
            "Ports / Hosts": "端口 / 主机",
            "Topology": "拓扑结构",
            "Host Details": "主机详情",
            "Scans": "扫描历史"
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
            self.output_tabs[key] = text_edit

        main_layout.addWidget(self.tab_widget)

        # ✅ 绑定标签页切换事件
        self.tab_widget.currentChanged.connect(self.on_tab_changed)

        # ===== 绑定按钮事件 =====
        self.scan_button.clicked.connect(self.on_scan_clicked)

        # 保存最新扫描结果（用于主机详情）
        self.latest_scan_results = []

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

    def draw_topology_graph(self):
        if not hasattr(self, "topology_figure"):
            return

        import networkx as nx

        self.topology_figure.clear()
        ax = self.topology_figure.add_subplot(111)

        G = nx.Graph()
        G.add_node("localhost")

        for item in self.latest_scan_results:
            if item.get("status") == "UP":
                ip = item.get("ip")
                G.add_node(ip)
                G.add_edge("localhost", ip)

        pos = nx.spring_layout(G)
        nx.draw(G, pos, ax=ax, with_labels=True, node_color="skyblue", edge_color="gray", node_size=1200, font_size=10)
        self.topology_canvas.draw()

    def create_new_window(self):
        new_win = MainWindow()
        new_win.show()
        if not hasattr(self, 'open_windows'):
            self.open_windows = []
        self.open_windows.append(new_win)

    def toggle_theme(self):
        if self.current_theme == "vscode":
            self.load_stylesheet("./ui/style/mac_light.qss")
            self.current_theme = "mac"
        else:
            self.load_stylesheet("./ui/style/vscode_dark.qss")
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
        elif profile == "端口扫描":
            self.thread = ScanThread(target, scan_type="port")
            self.thread.result_signal.connect(self.display_port_results)
        else:
            self.thread = ScanThread(target, scan_type="quick", scan_ports="80,443")
            self.thread.result_signal.connect(self.display_port_results)

        self.thread.start()

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

    def on_tab_changed(self, index):
        line = ""
        tab_name = self.tab_widget.tabText(index)
        if tab_name == "主机详情":
            self.output_tabs["Host Details"].clear()
            if not self.latest_scan_results:
                self.output_tabs["Host Details"].setText("尚无扫描结果。")
                return
            for item in self.latest_scan_results:
                ip = item.get("ip")
                if item.get("status") == "UP":
                    try:
                        os_result = os_fingerprint(ip)
                        line = f"{ip} - 识别到操作系统：{os_result}"
                    except Exception as e:
                        line = f"{ip} - 操作系统识别失败：{str(e)}"
                self.output_tabs["Host Details"].append(line)
        elif tab_name == "拓扑结构":
            self.draw_topology_graph()

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
