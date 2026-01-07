#!/usr/bin/env python3
import sys
from PyQt6.QtWidgets import QApplication
from gui import MobilytixGUI

def main():
    # Start the PyQt GUI only
    qt_app = QApplication(sys.argv)
    gui = MobilytixGUI()
    gui.show()
    sys.exit(qt_app.exec())

if __name__ == "__main__":
    main()
