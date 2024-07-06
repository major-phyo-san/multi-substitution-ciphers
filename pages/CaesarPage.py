import psutil
import time
import tracemalloc

from PyQt6.QtWidgets import QLabel, QVBoxLayout, QHBoxLayout, QWidget, QPushButton, QSpinBox, QTextEdit, QMessageBox
from PyQt6.QtCore import Qt

class CaesarPage(QWidget):
    def __init__(self,stack):
        super().__init__()

        self.stack = stack

        pageLabel = QLabel("Caesar Encryption")
        pageLabel.setStyleSheet("font-size: 24px; padding: 10px;")

        #  Create and configure labels
        self.shift_label = QLabel("Shift Number:")
        self.plaintext_label = QLabel("Plaintext:")
        self.ciphertext_label = QLabel("Ciphertext:")

        # Create and configure input fields
        self.shift_input = QSpinBox()
        self.shift_input.setRange(0, 25)
        # self.shift_input.setMinimum(0)
        # self.shift_input.setMaximum(25)
        self.shift_input.setValue(0)
        self.shift_input.setSingleStep(1)
        self.shift_input.setStyleSheet("font-size: 18px; padding: 5px; height: 30px; ")

        self.plaintext_input = QTextEdit()
        self.plaintext_input.setStyleSheet("font-size: 18px; padding: 5px; height: 80px;")

        self.ciphertext_output = QTextEdit()
        self.ciphertext_output.setStyleSheet("font-size: 18px; padding: 5px; height: 80px;")

        self.analysis_output_label = QLabel("Computational Analysis:")
        self.analysis_output = QTextEdit()
        self.analysis_output.setReadOnly(True)
        self.analysis_output.setStyleSheet("font-size: 13px; padding: 5px; height: 50px;")

        # Create and configure the "Encrypt, Decrypt" buttons
        encrypt_button = QPushButton("Encrypt")
        encrypt_button.setStyleSheet("font-size: 18px; padding: 10px;")
        encrypt_button.clicked.connect(self.encrypt_btn_clicked)

        decrypt_button = QPushButton("Decrypt")
        decrypt_button.setStyleSheet("font-size: 18px; padding: 10px;")
        decrypt_button.clicked.connect(self.decrypt_btn_clicked)

        # Layout for inputs
        input_layout = QVBoxLayout()
        input_layout.addWidget(self.shift_label)
        input_layout.addWidget(self.shift_input)
        input_layout.addWidget(self.plaintext_label)
        input_layout.addWidget(self.plaintext_input)
        input_layout.addWidget(self.ciphertext_label)
        input_layout.addWidget(self.ciphertext_output)
        input_layout.addWidget(self.analysis_output_label)
        input_layout.addWidget(self.analysis_output)

        # Layout for button
        button_layout = QHBoxLayout()
        button_layout.addStretch(1)
        button_layout.addWidget(encrypt_button)
        button_layout.addWidget(decrypt_button)
        button_layout.addStretch(1)

        back_button = QPushButton("Back")
        back_button.setStyleSheet("font-size: 18px; padding: 10px;")
        back_button.clicked.connect(self.go_back)

        layout = QVBoxLayout()
        layout.addWidget(pageLabel)
        layout.addLayout(input_layout)
        layout.addLayout(button_layout)
        layout.addWidget(back_button)
        layout.setAlignment(pageLabel, Qt.AlignmentFlag.AlignCenter)
        layout.setAlignment(back_button, Qt.AlignmentFlag.AlignCenter)

        self.setLayout(layout)

    def go_back(self):
        self.plaintext_input.setPlainText("")
        self.ciphertext_output.setPlainText("")
        self.analysis_output.setPlainText("")
        self.shift_input.setValue(0)
        self.stack.setCurrentIndex(0)

    def encrypt_btn_clicked(self):
        self.analysis_output.setPlainText("")
        shiftKey = self.shift_input.value()
        plainText = self.plaintext_input.toPlainText()
        if shiftKey < 0 or shiftKey > 25:
            QMessageBox.critical(self, "Error", "Shift value must be between 0 and 25")
            return 1
        if not plainText:
            QMessageBox.critical(self, "Error", "Plain text is empty")
            return 1
        
        tracemalloc.start()
        start_time = time.time()        
        self.encrypt(plainText, shiftKey)
        end_time = time.time()
        current, peak = tracemalloc.get_traced_memory()
        time_taken_ms = (end_time - start_time) * 1000
        cpu_usage, memory_usage = self.monitor_resources()

        timeTakenAnalysis = f"Time taken: {time_taken_ms:.2f} ms"
        cpuUsageAnalysis = f"CPU usage: {cpu_usage}%"        
        memoryUsageAnalysis = f"Memory usage: {peak / 10**3} KB"
        combinedAnalysis = f"{timeTakenAnalysis}\n{cpuUsageAnalysis}\n{memoryUsageAnalysis}"

        self.analysis_output.setPlainText(combinedAnalysis)

    def decrypt_btn_clicked(self):
        self.analysis_output.setPlainText("")
        shiftKey = self.shift_input.value()
        cipherText = self.ciphertext_output.toPlainText()
        if shiftKey < 0 or shiftKey > 25:
            QMessageBox.critical(self, "Error", "Shift value must be between 0 and 25")
            return 1
        if not cipherText:
            QMessageBox.critical(self, "Error", "Cipher text is empty")
            return 1
        
        tracemalloc.start()
        start_time = time.time()        
        self.decrypt(cipherText, shiftKey)
        end_time = time.time()
        current, peak = tracemalloc.get_traced_memory()
        time_taken_ms = (end_time - start_time) * 1000
        cpu_usage, memory_usage = self.monitor_resources()

        timeTakenAnalysis = f"Time taken: {time_taken_ms:.2f} ms"
        cpuUsageAnalysis = f"CPU usage: {cpu_usage}%"        
        memoryUsageAnalysis = f"Memory usage: {peak / 10**3} KB"
        combinedAnalysis = f"{timeTakenAnalysis}\n{cpuUsageAnalysis}\n{memoryUsageAnalysis}"

        self.analysis_output.setPlainText(combinedAnalysis)

    def encrypt(self, text, shift):
        result = ""
        for char in text:
            if char.isalpha():
                shift_base = 65 if char.isupper() else 97
                result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
            else:
                result += char
        self.ciphertext_output.setPlainText(result)
        return 0

    def decrypt(self, ciphertext, shift):
        result = ""
        for char in ciphertext:
            if char.isalpha():
                shift_base = 65 if char.isupper() else 97
                result += chr((ord(char) - shift_base - shift) % 26 + shift_base)
            else:
                result += char
        self.plaintext_input.setPlainText(result)

    def monitor_resources(self, interval=1):
        cpu_usage = psutil.cpu_percent(interval=interval)
        memory_info = psutil.virtual_memory()
        return cpu_usage, memory_info.percent