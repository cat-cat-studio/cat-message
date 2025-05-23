#python3
#user.py
#https://github.com/xhdndmm/cat-message

import sys
import socket
import json
import base64
import zlib
from datetime import datetime
from PyQt6.QtWidgets import  QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,QLineEdit, QPushButton, QTextEdit, QLabel, QMessageBox, QFileDialog
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QAction, QTextCursor, QImage, QTextImageFormat
import requests

REPO = "xhdndmm/cat-message"
CURRENT_VERSION = "v1.6" 

def send_message_with_length(sock, data_bytes):
    try:
        length = len(data_bytes)
        sock.sendall(length.to_bytes(4, byteorder='big'))
        sock.sendall(data_bytes)
    except Exception as e:
        QMessageBox.warning(None, "发送失败", f"发送数据失败: {str(e)}")

def read_message(sock):
    """读取网络消息并自动解压（带长度头）"""
    try:
        raw_length = sock.recv(4)
        if not raw_length:
            return None
        msg_length = int.from_bytes(raw_length, byteorder='big')
        buffer = bytearray()
        while len(buffer) < msg_length:
            chunk = sock.recv(min(4096, msg_length - len(buffer)))
            if not chunk:
                break
            buffer.extend(chunk)
        try:
            decompressed = zlib.decompress(base64.b64decode(buffer))
            return decompressed
        except Exception as e:
            QMessageBox.warning(None, "接收失败", f"解压缩失败: {str(e)}")
            return base64.b64decode(buffer)
    except Exception as e:
        QMessageBox.warning(None, "接收失败", f"读取消息失败: {str(e)}")
        return None

class ChatReceiver(QThread):
    """消息接收线程，处理网络通信"""
    # 修改信号，带上图片数据
    new_message = pyqtSignal(str, str, object)  # text, msg_type, img_data
    update_online_users = pyqtSignal(int)
    
    def __init__(self, client_socket):
        super().__init__()
        self.client_socket = client_socket
        self.running = True
        
    def run(self):
        while self.running:
            try:
                raw_data = read_message(self.client_socket)
                if not raw_data:
                    break
                data = json.loads(raw_data.decode('utf-8'))
                # 处理历史消息
                if data.get("type") == "history":
                    for msg in data["data"]:
                        self.process_message(msg)
                # 处理在线人数
                elif data.get("type") == "online_users":
                    self.update_online_users.emit(data["count"])
                # 处理普通消息
                else:
                    self.process_message(data)
            except Exception as e:
                break

    def process_message(self, data):
        """统一处理消息并发射信号"""
        msg_type = data.get("content_type", "text")
        if msg_type == "image":
            text = f"{data['username']} ({data.get('time', 'unknown')}) [图片]:"
            self.new_message.emit(text, "image", data["message"])
        else:
            text = f"{data['username']} ({data.get('time', 'unknown')}, {data.get('ip', 'unknown')}): {data['message']}"
            self.new_message.emit(text, "text", None)

    def stop(self):
        self.running = False
        self.quit()
        self.wait()

class MainWindow(QMainWindow):
    """主窗口类"""
    def __init__(self):
        super().__init__()
        self.setWindowOpacity(0.95)
        self.init_ui()
        self.setup_toolbar()
        self.client_socket = None
        self.receiver_thread = None

    def init_ui(self):
        """初始化界面"""
        self.setWindowTitle(f"cat-message-user-{CURRENT_VERSION}")
        central = QWidget()
        self.setCentralWidget(central)
        
        # 连接信息区域
        h_conn = QHBoxLayout()
        h_conn.addWidget(QLabel("服务器地址:"))
        self.server_ip_edit = QLineEdit()
        h_conn.addWidget(self.server_ip_edit)
        h_conn.addWidget(QLabel("端口:"))
        self.server_port_edit = QLineEdit("12345")
        h_conn.addWidget(self.server_port_edit)
        h_conn.addWidget(QLabel("用户名:"))
        self.username_edit = QLineEdit()
        h_conn.addWidget(self.username_edit)
        self.connect_btn = QPushButton("连接")
        self.connect_btn.clicked.connect(self.connect_to_server)
        h_conn.addWidget(self.connect_btn)
        
        # 聊天区域
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        
        # 功能按钮区域
        h_func = QHBoxLayout()
        self.load_history_btn = QPushButton("加载记录")
        self.load_history_btn.clicked.connect(self.load_history)
        self.disconnect_btn = QPushButton("断开")
        self.disconnect_btn.clicked.connect(self.disconnect_from_server)
        self.btn_upload = QPushButton("发送图片")
        self.btn_upload.clicked.connect(self.send_image)
        h_func.addWidget(self.load_history_btn)
        h_func.addWidget(self.disconnect_btn)
        h_func.addWidget(self.btn_upload)
        
        # 消息输入区域
        h_msg = QHBoxLayout()
        self.message_edit = QLineEdit()
        self.send_btn = QPushButton("发送")
        self.send_btn.clicked.connect(self.send_message)
        h_msg.addWidget(self.message_edit)
        h_msg.addWidget(self.send_btn)
        
        # 主布局
        v_layout = QVBoxLayout()
        v_layout.addLayout(h_conn)
        v_layout.addWidget(self.chat_area)
        v_layout.addLayout(h_func)
        v_layout.addLayout(h_msg)
        central.setLayout(v_layout)

    def setup_toolbar(self):
        """初始化工具栏"""
        toolbar = self.addToolBar("功能栏")
        toolbar.setMovable(False)
        # 检查更新按钮
        check_update_action = QAction("检查更新", self)
        check_update_action.triggered.connect(MainWindow.check_for_update)
        toolbar.addAction(check_update_action)
        # 关于按钮
        about_action = QAction("关于", self)
        about_action.triggered.connect(self.show_about)
        toolbar.addAction(about_action)
        # 在线人数显示
        self.online_users_label = QLabel("在线: 0")
        toolbar.addWidget(self.online_users_label)

    def send_image(self):
        """发送图片处理"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择图片", "", "Images (*.png *.jpg *.jpeg)")
        if not file_path:
            return
        
        # 读取并编码图片
        with open(file_path, "rb") as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        
        # 构建消息
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        payload = {
            "username": self.username_edit.text().strip(),
            "message": img_data,
            "time": current_time,
            "content_type": "image"
        }
        self.send_payload(payload)
        self.append_message(f"You ({current_time}) [图片]:", "image", img_data)

    #连接服务器
    def connect_to_server(self):
        server_ip = self.server_ip_edit.text().strip()
        server_port = self.server_port_edit.text().strip()
        username = self.username_edit.text().strip()
        if not server_ip or not username:
            QMessageBox.warning(self, "警告", "请输入服务器地址和用户名")
            return
        if not server_port.isdigit():
            QMessageBox.warning(self, "警告", "端口号必须是数字")
            return
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10)  # 设置连接超时时间为10秒
            self.client_socket.connect((server_ip, int(server_port)))
            self.client_socket.settimeout(None)  # 连接成功后取消超时限制
            verify_payload = {"command": "verify", "payload": "cat-message-v1.6"}
            json_verify = json.dumps(verify_payload).encode('utf-8')
            compressed_verify = zlib.compress(json_verify)
            encrypted_verify = base64.b64encode(compressed_verify)
            send_message_with_length(self.client_socket, encrypted_verify)
            self.client_socket.settimeout(5)
            response_data = read_message(self.client_socket)
            self.client_socket.settimeout(None)
            if not response_data:
                raise Exception("未收到验证响应")
            decompressed_resp = response_data.decode('utf-8')
            resp = json.loads(decompressed_resp)
            if not (resp.get("type") == "verify" and resp.get("status") == "ok"):
                QMessageBox.warning(self, "验证失败", f"服务器验证失败: {resp.get('message', '未知错误')}")
                self.disconnect_from_server()
                return
        except socket.timeout:
            self.disconnect_from_server()
            QMessageBox.warning(self, "连接超时", "无法连接到服务器，请检查网络或服务器地址")
            return
        except Exception as e:
            self.disconnect_from_server()
            QMessageBox.critical(self, "连接失败", f"连接服务器时发生错误:\n{repr(e)}")
            return
        self.server_ip_edit.setDisabled(True)
        self.username_edit.setDisabled(True)
        self.connect_btn.setDisabled(True)
        self.receiver_thread = ChatReceiver(self.client_socket)
        self.receiver_thread.new_message.connect(self.update_chat)
        self.receiver_thread.update_online_users.connect(self.update_online_users)
        self.receiver_thread.start()

    def send_message(self):
        """发送文本消息"""
        message = self.message_edit.text().strip()
        if not message:
            return
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        payload = {
            "username": self.username_edit.text().strip(),
            "message": message,
            "time": current_time,
            "content_type": "text"
        }
        self.send_payload(payload)
        self.append_message(f"You ({current_time}): {message}", "text")
        self.message_edit.clear()

    def send_payload(self, payload):
        """发送消息通用方法（含压缩和长度头）"""
        try:
            json_data = json.dumps(payload).encode('utf-8')
            compressed = zlib.compress(json_data)  # 压缩数据
            encrypted = base64.b64encode(compressed)
            send_message_with_length(self.client_socket, encrypted)
        except Exception as e:
            QMessageBox.warning(self, "错误", "发送失败")

    def append_message(self, text, msg_type, img_data=None):
        """向聊天框添加消息"""
        if msg_type == "image":
            cursor = self.chat_area.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            # 插入文本并换行（确保文本和图片之间有空行）
            cursor.insertBlock()
            cursor.insertText(text)
            cursor.insertBlock()
            # 插入图片
            image_format = QTextImageFormat()
            image_format.setWidth(200)  # 限制图片宽度
            image_format.setName(f"data:image/png;base64,{img_data}")
            cursor.insertImage(image_format)
            cursor.insertBlock()  # 图片后再换行
        else:
            self.chat_area.append(text)
        
    def load_history(self):
        if not self.client_socket:
            QMessageBox.warning(self, "警告", "尚未连接服务器")
            return
        self.chat_area.clear()
        try:
            payload = {"command": "load_history"}
            json_payload = json.dumps(payload).encode('utf-8')
            compressed = zlib.compress(json_payload)
            encrypted = base64.b64encode(compressed)
            send_message_with_length(self.client_socket, encrypted)
        except Exception as e:
            QMessageBox.warning(self, "加载错误", "加载聊天记录失败")

    def update_chat(self, text, msg_type="text", img_data=None):
        # 统一处理图片和文本
        if msg_type == "image" and img_data:
            self.append_message(text, "image", img_data)
        else:
            self.append_message(text, "text")

    def update_online_users(self, count):
        self.online_users_label.setText(f"在线人数: {count}")
        
    def disconnect_from_server(self):
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.client_socket.close()
            except Exception:
                pass
            self.client_socket = None
        if self.receiver_thread:
            self.receiver_thread.running = False  # 确保线程能退出
            self.receiver_thread.quit()
            self.receiver_thread.wait(2000)  # 最多等2秒，防止卡死
            self.receiver_thread = None
        self.server_ip_edit.setDisabled(False)
        self.username_edit.setDisabled(False)
        self.connect_btn.setDisabled(False)
        self.update_chat("已断开与服务器的连接。")
        
    def show_about(self):
        QMessageBox.information(self, "关于", '<a href="https://github.com/xhdndmm/cat-message">cat-message-user-v1.6</a><br><a href="https://docs.cat-message.xhdndmm.cn">使用文档</a>')
        
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
     
    def get_latest_github_release(repo):
        try:
            url = f"https://api.github.com/repos/{repo}/releases/latest"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data.get("tag_name", None)
        except requests.RequestException as e:
            QMessageBox.warning(None, "更新检查失败", f"无法检查更新: {str(e)}")
            return None

    def check_for_update():
        latest_version = MainWindow.get_latest_github_release(REPO)
        if latest_version is None:
            return
        if latest_version == CURRENT_VERSION:
            QMessageBox.information(None, "检查更新", "当前已是最新版本")
        else:
            QMessageBox.information(None, "检查更新", f"发现新版本: {latest_version}\n注意：不要随便升级，本项目需要确认服务端版本和客户端版本是否一致！")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())