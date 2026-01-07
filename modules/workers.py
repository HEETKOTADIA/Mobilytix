from PyQt6.QtCore import QThread, pyqtSignal

class Worker(QThread):
    finished = pyqtSignal(object)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            result = self.fn()
        except Exception as e:
            result = f"Error: {e}"
        self.finished.emit(result)
