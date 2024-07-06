from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget, QPushButton
from PyQt6.QtCore import Qt

class AffinePage(QWidget):
    def __init__(self, stack):
        super().__init__()

        self.stack = stack

        label = QLabel("Welcome to Affine Encryption")
        label.setStyleSheet("font-size: 24px; padding: 10px;")

        back_button = QPushButton("Back")
        back_button.setStyleSheet("font-size: 18px; padding: 10px;")
        back_button.clicked.connect(self.go_back)

        layout = QVBoxLayout()
        layout.addWidget(label)
        layout.addWidget(back_button)
        layout.setAlignment(label, Qt.AlignmentFlag.AlignCenter)
        layout.setAlignment(back_button, Qt.AlignmentFlag.AlignCenter)

        self.setLayout(layout)

    def go_back(self):
        self.stack.setCurrentIndex(0)