#https://github.com/xhdndmm/cat-message

import sys
import socket
import json
import base64
from datetime import datetime
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QTextEdit, QLabel, QMessageBox
from PyQt5.QtCore import QThread, pyqtSignal

def read_message(sock):
    buffer = bytearray()
    while True:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buffer.extend(chunk)
        if len(chunk) < 1024:
            break
    return bytes(buffer)

class ChatReceiver(QThread):
    new_message = pyqtSignal(str)
    
    def __init__(self, client_socket):
        super().__init__()
        self.client_socket = client_socket
        self.running = True
        
    def run(self):
        while self.running:
            try:
                combined = read_message(self.client_socket)
                if not combined:
                    break
                decoded = base64.b64decode(combined).decode('utf-8')
                data = json.loads(decoded)
                if data.get("type") == "history":
                    for msg in data["data"]:
                        text = f"{msg['username']} ({msg['time']}, {msg.get('ip', 'unknown')}): {msg['message']}"
                        self.new_message.emit(text)
                else:
                    text = f"{data['username']} ({data.get('time', 'unknown')}, {data.get('ip', 'unknown')}): {data['message']}"
                    self.new_message.emit(text)
            except Exception as e:
                break

    def stop(self):
        self.running = False
        self.quit()
        self.wait()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.client_socket = None
        self.receiver_thread = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("cat-message-user-v1.2")
        central = QWidget()
        self.setCentralWidget(central)
        v_layout = QVBoxLayout()
        h_conn = QHBoxLayout()
        h_conn.addWidget(QLabel("服务器IP:"))
        self.server_ip_edit = QLineEdit()
        h_conn.addWidget(self.server_ip_edit)
        h_conn.addWidget(QLabel("用户名:"))
        self.username_edit = QLineEdit()
        h_conn.addWidget(self.username_edit)
        self.connect_btn = QPushButton("连接")
        self.connect_btn.clicked.connect(self.connect_to_server)
        h_conn.addWidget(self.connect_btn)
        v_layout.addLayout(h_conn)
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        v_layout.addWidget(self.chat_area)
        h_msg = QHBoxLayout()
        self.message_edit = QLineEdit()
        h_msg.addWidget(self.message_edit)
        self.send_btn = QPushButton("发送")
        self.send_btn.clicked.connect(self.send_message)
        h_msg.addWidget(self.send_btn)
        v_layout.addLayout(h_msg)
        central.setLayout(v_layout)
        
    def connect_to_server(self):
        server_ip = self.server_ip_edit.text().strip()
        username = self.username_edit.text().strip()
        if not server_ip or not username:
            QMessageBox.warning(self, "警告", "请输入服务器IP和用户名")
            return
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((server_ip, 12345))
        except Exception as e:
            retry = QMessageBox.question(self, "连接错误", "无法连接到服务器，是否重试？\n取消以更改服务器IP。",
                                         QMessageBox.Retry | QMessageBox.Cancel)
            if retry == QMessageBox.Retry:
                self.connect_to_server()
            else:
                return
        self.server_ip_edit.setDisabled(True)
        self.username_edit.setDisabled(True)
        self.connect_btn.setDisabled(True)
        self.receiver_thread = ChatReceiver(self.client_socket)
        self.receiver_thread.new_message.connect(self.update_chat)
        self.receiver_thread.start()
        
    def send_message(self):
        message = self.message_edit.text().strip()
        if not message:
            return
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        username = self.username_edit.text().strip()
        payload = {"username": username, "message": message, "time": current_time}
        json_payload = json.dumps(payload)
        try:
            encrypted = base64.b64encode(json_payload.encode('utf-8'))
            self.client_socket.sendall(encrypted)
            self.update_chat(f"You ({current_time}): {message}")
        except Exception as e:
            QMessageBox.warning(self, "发送错误", "消息发送失败")
        self.message_edit.clear()
        
    def update_chat(self, msg):
        self.chat_area.append(msg)
        
    def closeEvent(self, event):
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
        if self.receiver_thread:
            self.receiver_thread.stop()
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception:
                pass
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())