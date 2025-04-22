import sys
from PyQt5.QtWidgets import QApplication
from ui.main_window import MainWindow
from core.utils import resource_path

def main():
    app = QApplication(sys.argv)

    # 设置应用样式
    with open(resource_path("ui/style/mac_light.qss"), "r", encoding="utf-8") as f:
        app.setStyleSheet(f.read())


    # 启动主窗口
    window = MainWindow()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
