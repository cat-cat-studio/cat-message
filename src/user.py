#python3
#user.py
#https://github.com/xhdndmm/cat-message

import sys
import socket
import json
import base64
import zlib
from datetime import datetime
from PyQt6.QtWidgets import  QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,QLineEdit, QPushButton, QTextEdit, QLabel, QMessageBox, QFileDialog, QComboBox
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QUrl, QMimeData
from PyQt6.QtGui import QAction, QTextCursor, QImage, QTextImageFormat, QDrag
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

REPO = "xhdndmm/cat-message"
CURRENT_VERSION = "v1.8" 

class RSACrypto:
    def __init__(self):
        self.key = None
        self.public_key = None
        self.private_key = None
        self.peer_public_key = None
        
    def generate_key_pair(self, key_size):
        """生成RSA密钥对"""
        self.key = RSA.generate(key_size)
        self.public_key = self.key.publickey()
        self.private_key = self.key
        
    def export_public_key(self):
        """导出公钥"""
        return self.public_key.export_key()
        
    def import_peer_public_key(self, key_data):
        """导入对方公钥"""
        self.peer_public_key = RSA.import_key(key_data)
        
    def encrypt(self, data):
        """使用对方公钥加密数据"""
        if not self.peer_public_key:
            raise Exception("Peer public key not set")
        cipher = PKCS1_OAEP.new(self.peer_public_key)
        return cipher.encrypt(data)
        
    def decrypt(self, encrypted_data):
        """使用自己的私钥解密数据"""
        if not self.private_key:
            raise Exception("Private key not set")
        cipher = PKCS1_OAEP.new(self.private_key)
        return cipher.decrypt(encrypted_data)

def send_message_with_length(sock, data_bytes):
    try:
        length = len(data_bytes)
        sock.sendall(length.to_bytes(4, byteorder='big'))
        sock.sendall(data_bytes)
    except Exception as e:
        QMessageBox.warning(None, "发送失败", f"发送数据失败: {str(e)}")

def read_message(sock):
    """读取网络消息"""
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
        return buffer
    except Exception as e:
        QMessageBox.warning(None, "接收失败", f"读取消息失败: {str(e)}")
        return None

class ChatReceiver(QThread):
    """消息接收线程，处理网络通信"""
    new_message = pyqtSignal(str, str, object)  # text, msg_type, img_data
    update_online_users = pyqtSignal(int)
    
    def __init__(self, client_socket, crypto):
        super().__init__()
        self.client_socket = client_socket
        self.crypto = crypto  # 可能为None（无加密模式）
        self.running = True
        
    def run(self):
        while self.running:
            try:
                raw_data = read_message(self.client_socket)
                if not raw_data:
                    break
                    
                # 根据是否有加密决定处理方式
                if self.crypto:
                    # 解密消息
                    decrypted_data = self.crypto.decrypt(raw_data)
                    data = json.loads(decrypted_data.decode('utf-8'))
                else:
                    # 无加密模式，直接解析
                    data = json.loads(raw_data.decode('utf-8'))
                
                # 处理历史消息
                if data.get("type") == "history":
                    for msg in data["data"]:
                        self.process_message(msg)
                # 处理在线人数
                elif data.get("type") == "online_users":
                    self.update_online_users.emit(data["count"])
                # 处理错误消息
                elif data.get("type") == "error":
                    QMessageBox.warning(None, "服务器错误", data.get("message", "未知错误"))
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
            # 从服务器获取图片数据
            try:
                response = requests.get(f"http://{self.client_socket.getpeername()[0]}:12346/image/{data['message']}")
                if response.status_code == 200:
                    self.new_message.emit(text, "image", response.content)
                else:
                    QMessageBox.warning(None, "获取图片失败", f"无法获取图片，状态码: {response.status_code}")
            except Exception as e:
                QMessageBox.warning(None, "获取图片失败", f"无法获取图片: {str(e)}")
        elif msg_type == "file":
            file_name = data.get("file_name", "未知文件")
            file_size = data.get("file_size", 0)
            text = f"{data['username']} ({data.get('time', 'unknown')}) [文件: {file_name}]:"
            
            # 下载文件到本地临时目录
            try:
                response = requests.get(f"http://{self.client_socket.getpeername()[0]}:12346/file/{data['message']}")
                if response.status_code == 200:
                    # 创建临时目录
                    import tempfile
                    import os
                    temp_dir = tempfile.gettempdir()
                    local_file_path = os.path.join(temp_dir, "cat_message_files", file_name)
                    
                    # 确保目录存在
                    os.makedirs(os.path.dirname(local_file_path), exist_ok=True)
                    
                    # 保存文件
                    with open(local_file_path, 'wb') as f:
                        f.write(response.content)
                    
                    self.new_message.emit(text, "file", {
                        "name": file_name, 
                        "size": file_size, 
                        "local_path": local_file_path
                    })
                else:
                    # 下载失败，显示错误信息
                    self.new_message.emit(text, "file", {
                        "name": file_name, 
                        "size": file_size, 
                        "error": "下载失败"
                    })
            except Exception as e:
                self.new_message.emit(text, "file", {
                    "name": file_name, 
                    "size": file_size, 
                    "error": str(e)
                })
        else:
            text = f"{data['username']} ({data.get('time', 'unknown')}, {data.get('ip', 'unknown')}): {data['message']}"
            self.new_message.emit(text, "text", None)

    def stop(self):
        self.running = False
        self.quit()
        self.wait()

class ConnectThread(QThread):
    """连接线程，处理连接逻辑"""
    connection_success = pyqtSignal(socket.socket, object)  # crypto可能为None
    connection_error = pyqtSignal(str)
    status_update = pyqtSignal(str)
    
    def __init__(self, server_ip, server_port, username, encryption_mode):
        super().__init__()
        self.server_ip = server_ip
        self.server_port = server_port
        self.username = username
        self.encryption_mode = encryption_mode
        self.running = True
        
    def run(self):
        try:
            self.status_update.emit("正在连接服务器...")
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10)
            client_socket.connect((self.server_ip, self.server_port))
            client_socket.settimeout(None)
            
            crypto = None
            
            # 根据加密模式处理
            if self.encryption_mode == "无加密":
                # 发送兼容性验证
                verify_payload = {"command": "verify", "payload": "cat-message-v1.8-noenc"}
                send_message_with_length(client_socket, json.dumps(verify_payload).encode('utf-8'))
                
                response = read_message(client_socket)
                if not response:
                    raise Exception("未收到服务器响应")
                    
                response_data = json.loads(response.decode('utf-8'))
                if not (response_data.get("type") == "verify" and response_data.get("status") == "ok"):
                    raise Exception(f"验证失败: {response_data.get('message', '未知错误')}")
                    
            else:
                # 加密模式
                key_size = {"RSA2048": 2048, "RSA4096": 4096, "RSA8192": 8192}[self.encryption_mode]
                
                self.status_update.emit("正在生成加密密钥...")
                crypto = RSACrypto()
                crypto.generate_key_pair(key_size)
                
                # 发送验证信息
                verify_payload = {"command": "verify", "payload": f"cat-message-v1.8-enc-{key_size}"}
                send_message_with_length(client_socket, json.dumps(verify_payload).encode('utf-8'))
                
                # 等待服务器响应
                response = read_message(client_socket)
                if not response:
                    raise Exception("未收到服务器响应")
                    
                response_data = json.loads(response.decode('utf-8'))
                if not (response_data.get("type") == "verify" and response_data.get("status") == "ok"):
                    raise Exception(f"验证失败: {response_data.get('message', '未知错误')}")
                    
                # 导入服务器公钥
                crypto.import_peer_public_key(base64.b64decode(response_data["public_key"]))
                
                # 发送客户端公钥
                key_payload = {
                    "type": "public_key",
                    "public_key": base64.b64encode(crypto.export_public_key()).decode('utf-8')
                }
                send_message_with_length(client_socket, json.dumps(key_payload).encode('utf-8'))
            
            self.connection_success.emit(client_socket, crypto)
            
        except socket.timeout:
            self.connection_error.emit("连接超时，请检查网络或服务器地址")
        except Exception as e:
            self.connection_error.emit(f"连接服务器时发生错误:\n{repr(e)}")
        finally:
            self.running = False

class MainWindow(QMainWindow):
    """主窗口类"""
    def __init__(self):
        super().__init__()
        self.setWindowOpacity(0.95)
        self.init_ui()
        self.setup_toolbar()
        self.client_socket = None
        self.receiver_thread = None
        self.crypto = None
        self.file_paths = {}

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
        
        # 加密模式选择
        h_conn.addWidget(QLabel("加密模式:"))
        self.encryption_mode_edit = QComboBox()
        self.encryption_mode_edit.addItems(["无加密", "RSA2048", "RSA4096", "RSA8192"])
        self.encryption_mode_edit.setCurrentText("RSA4096")  # 默认选择RSA4096
        h_conn.addWidget(self.encryption_mode_edit)
        
        self.connect_btn = QPushButton("连接")
        self.connect_btn.clicked.connect(self.connect_to_server)
        h_conn.addWidget(self.connect_btn)
        
        # 聊天区域
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        self.chat_area.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.chat_area.customContextMenuRequested.connect(self.show_context_menu)
        self.chat_area.mouseDoubleClickEvent = self.on_chat_area_double_click
        self.chat_area.mousePressEvent = self.on_chat_area_mouse_press
        self.chat_area.mouseMoveEvent = self.on_chat_area_mouse_move
        
        # 功能按钮区域
        h_func = QHBoxLayout()
        self.load_history_btn = QPushButton("加载记录")
        self.load_history_btn.clicked.connect(self.load_history)
        self.disconnect_btn = QPushButton("断开")
        self.disconnect_btn.clicked.connect(self.disconnect_from_server)
        self.btn_upload = QPushButton("发送图片")
        self.btn_upload.clicked.connect(self.send_image)
        self.btn_send_file = QPushButton("发送文件")
        self.btn_send_file.clicked.connect(self.send_file)
        h_func.addWidget(self.load_history_btn)
        h_func.addWidget(self.disconnect_btn)
        h_func.addWidget(self.btn_upload)
        h_func.addWidget(self.btn_send_file)
        
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
        # 清理缓存按钮
        clear_cache_action = QAction("清理缓存", self)
        clear_cache_action.triggered.connect(self.clear_file_cache)
        toolbar.addAction(clear_cache_action)
        # 关于按钮
        about_action = QAction("关于", self)
        about_action.triggered.connect(self.show_about)
        toolbar.addAction(about_action)
        # 在线人数显示
        self.online_users_label = QLabel("在线: 0")
        toolbar.addWidget(self.online_users_label)

    def send_file(self):
        """发送文件处理"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "All Files (*.*)")
        if not file_path:
            return
        
        import os
        file_size = os.path.getsize(file_path)
        
        # 读取文件数据
        with open(file_path, "rb") as f:
            file_data = f.read()
        
        # 获取文件名
        file_name = os.path.basename(file_path)
        
        # 构建消息
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        payload = {
            "username": self.username_edit.text().strip(),
            "message": base64.b64encode(file_data).decode('utf-8'),
            "time": current_time,
            "content_type": "file",
            "file_name": file_name,
            "file_size": file_size
        }
        self.send_payload(payload)
        self.append_message(f"You ({current_time}) [文件: {file_name}]:", "file", {"name": file_name, "size": file_size})

    def send_image(self):
        """发送图片处理"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择图片", "", "Images (*.png *.jpg *.jpeg)")
        if not file_path:
            return
        
        # 读取图片数据
        with open(file_path, "rb") as f:
            img_data = f.read()
        
        # 构建消息
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        payload = {
            "username": self.username_edit.text().strip(),
            "message": base64.b64encode(img_data).decode('utf-8'),
            "time": current_time,
            "content_type": "image"
        }
        self.send_payload(payload)
        self.append_message(f"You ({current_time}) [图片]:", "image", img_data)

    def connect_to_server(self):
        server_ip = self.server_ip_edit.text().strip()
        server_port = self.server_port_edit.text().strip()
        username = self.username_edit.text().strip()
        encryption_mode = self.encryption_mode_edit.currentText()
        if not server_ip or not username:
            QMessageBox.warning(self, "警告", "请输入服务器地址和用户名")
            return
        if not server_port.isdigit():
            QMessageBox.warning(self, "警告", "端口号必须是数字")
            return
            
        # 禁用连接按钮并显示连接状态
        self.connect_btn.setDisabled(True)
        self.connect_btn.setText("连接中...")
        
        # 创建连接线程
        self.connect_thread = ConnectThread(server_ip, int(server_port), username, encryption_mode)
        self.connect_thread.connection_success.connect(self.on_connection_success)
        self.connect_thread.connection_error.connect(self.on_connection_error)
        self.connect_thread.status_update.connect(self.on_status_update)
        self.connect_thread.start()

    def on_status_update(self, status):
        """更新连接状态"""
        self.connect_btn.setText(status)
        
    def on_connection_success(self, client_socket, crypto):
        """连接成功回调"""
        self.client_socket = client_socket
        self.crypto = crypto
        
        self.server_ip_edit.setDisabled(True)
        self.username_edit.setDisabled(True)
        self.connect_btn.setText("连接")
        self.connect_btn.setDisabled(True)
        
        self.receiver_thread = ChatReceiver(self.client_socket, self.crypto)
        self.receiver_thread.new_message.connect(self.update_chat)
        self.receiver_thread.update_online_users.connect(self.update_online_users)
        self.receiver_thread.start()
        
    def on_connection_error(self, error_msg):
        """连接失败回调"""
        self.connect_btn.setText("连接")
        self.connect_btn.setDisabled(False)
        QMessageBox.critical(self, "连接失败", error_msg)

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
        """发送消息通用方法"""
        try:
            if self.crypto:
                # 加密模式
                encrypted_data = self.crypto.encrypt(json.dumps(payload).encode('utf-8'))
                send_message_with_length(self.client_socket, encrypted_data)
            else:
                # 无加密模式
                send_message_with_length(self.client_socket, json.dumps(payload).encode('utf-8'))
        except Exception as e:
            QMessageBox.warning(self, "错误", "发送失败")

    def append_message(self, text, msg_type, data=None):
        """向聊天框添加消息"""
        if msg_type == "image":
            cursor = self.chat_area.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            cursor.insertBlock()
            cursor.insertText(text)
            cursor.insertBlock()
            image_format = QTextImageFormat()
            image_format.setWidth(200)
            image_format.setName(f"data:image/png;base64,{base64.b64encode(data).decode('utf-8')}")
            cursor.insertImage(image_format)
            cursor.insertBlock()
        elif msg_type == "file":
            cursor = self.chat_area.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            cursor.insertBlock()
            cursor.insertText(text)
            cursor.insertBlock()
            
            if data:
                if "local_path" in data:
                    # 文件已下载到本地
                    file_info = f"📁 {data['name']} ({self.format_file_size(data['size'])})"
                    cursor.insertText(file_info)
                    cursor.insertBlock()
                    cursor.insertText("✅ 文件已下载到本地，到文件管理器")
                    cursor.insertBlock()
                    
                    # 保存文件路径
                    import os
                    file_folder = os.path.dirname(data["local_path"])
                    # 存储文件信息以便拖拽
                    file_id = len(self.file_paths)
                    self.file_paths[file_id] = {
                        'path': data["local_path"],
                        'name': data["name"],
                        'folder': file_folder
                    }
                    
                    cursor.insertText(f"📂 双击打开文件夹: {file_folder}")
                    
                elif "error" in data:
                    # 显示错误信息
                    cursor.insertText(f"📁 {data['name']} ({self.format_file_size(data['size'])}) - ❌ {data['error']}")
                else:
                    # 自己发送的文件
                    file_info = f"📁 {data['name']} ({self.format_file_size(data['size'])})"
                    cursor.insertText(file_info)
            cursor.insertBlock()
        else:
            self.chat_area.append(text)
        
    def format_file_size(self, size):
        """格式化文件大小显示"""
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size // 1024} KB"
        else:
            return f"{size // (1024 * 1024)} MB"

    def load_history(self):
        if not self.client_socket:
            QMessageBox.warning(self, "警告", "尚未连接服务器")
            return
        self.chat_area.clear()
        try:
            payload = {"command": "load_history"}
            if self.crypto:
                encrypted_data = self.crypto.encrypt(json.dumps(payload).encode('utf-8'))
                send_message_with_length(self.client_socket, encrypted_data)
            else:
                send_message_with_length(self.client_socket, json.dumps(payload).encode('utf-8'))
        except Exception as e:
            QMessageBox.warning(self, "加载错误", "加载聊天记录失败")

    def update_chat(self, text, msg_type="text", data=None):
        if msg_type == "image" and data:
            self.append_message(text, "image", data)
        elif msg_type == "file" and data:
            self.append_message(text, "file", data)
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
            self.receiver_thread.running = False
            self.receiver_thread.quit()
            self.receiver_thread.wait(2000)
            self.receiver_thread = None
        self.server_ip_edit.setDisabled(False)
        self.username_edit.setDisabled(False)
        self.connect_btn.setDisabled(False)
        self.update_chat("已断开与服务器的连接。")
        
    def show_about(self):
        QMessageBox.information(self, "关于", '<a href="https://github.com/xhdndmm/cat-message">cat-message-user-v1.8</a><br><a href="https://docs.cat-message.xhdndmm.cn">使用文档</a>')
        
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

    def show_context_menu(self, pos):
        """显示右键菜单"""
        cursor = self.chat_area.cursorForPosition(pos)
        cursor.select(QTextCursor.SelectionType.LineUnderCursor)
        selected_text = cursor.selectedText()
        
        # 检查是否点击在文件路径行
        if "📂 双击打开文件夹:" in selected_text:
            from PyQt6.QtWidgets import QMenu
            menu = QMenu(self.chat_area)
            
            open_folder_action = menu.addAction("📂 打开文件夹")
            copy_path_action = menu.addAction("📋 复制路径")
            
            action = menu.exec(self.chat_area.mapToGlobal(pos))
            
            if action == open_folder_action:
                path = selected_text.replace("📂 双击打开文件夹: ", "").strip()
                self.open_file_folder(path)
            elif action == copy_path_action:
                path = selected_text.replace("📂 双击打开文件夹: ", "").strip()
                QApplication.clipboard().setText(path)
                
    def on_chat_area_double_click(self, event):
        """处理聊天区域双击事件"""
        cursor = self.chat_area.cursorForPosition(event.pos())
        cursor.select(QTextCursor.SelectionType.LineUnderCursor)
        selected_text = cursor.selectedText()
        
        # 如果双击的是文件夹路径行，打开文件夹
        if "📂 双击打开文件夹:" in selected_text:
            path = selected_text.replace("📂 双击打开文件夹: ", "").strip()
            self.open_file_folder(path)
            
    def open_file_folder(self, folder_path):
        """打开文件所在的文件夹"""
        import os
        import platform
        import subprocess
        
        if not os.path.exists(folder_path):
            QMessageBox.warning(self, "错误", "文件夹不存在")
            return
            
        try:
            if platform.system() == "Windows":
                os.startfile(folder_path)
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(["open", folder_path])
            else:  # Linux
                subprocess.run(["xdg-open", folder_path])
        except Exception as e:
            QMessageBox.warning(self, "错误", f"无法打开文件夹: {str(e)}")

    def on_chat_area_mouse_press(self, event):
        """处理聊天区域鼠标按下事件"""
        if event.button() == Qt.MouseButton.LeftButton:
            self.drag_start_position = event.pos()
        # 调用原始的鼠标按下事件
        QTextEdit.mousePressEvent(self.chat_area, event)
        
    def on_chat_area_mouse_move(self, event):
        """处理聊天区域鼠标移动事件"""
        import os
        
        if not (event.buttons() & Qt.MouseButton.LeftButton):
            QTextEdit.mouseMoveEvent(self.chat_area, event)
            return
            
        if not hasattr(self, 'drag_start_position'):
            QTextEdit.mouseMoveEvent(self.chat_area, event)
            return
            
        if ((event.pos() - self.drag_start_position).manhattanLength() < 
            QApplication.startDragDistance()):
            QTextEdit.mouseMoveEvent(self.chat_area, event)
            return
            
        # 检查当前位置是否有文件
        cursor = self.chat_area.cursorForPosition(event.pos())
        cursor.select(QTextCursor.SelectionType.LineUnderCursor)
        selected_text = cursor.selectedText()
        
        file_path = None
        if "📁" in selected_text and "(" in selected_text:
            # 这是一个文件行，查找对应的路径
            cursor.movePosition(QTextCursor.MoveOperation.Down)
            cursor.select(QTextCursor.SelectionType.LineUnderCursor)
            next_line = cursor.selectedText()
            
            if "📂 双击打开文件夹:" in next_line:
                # 找到文件夹路径，推算文件路径
                folder_path = next_line.replace("📂 双击打开文件夹: ", "").strip()
                # 从存储的文件路径中查找匹配的文件
                for file_info in self.file_paths.values():
                    if file_info['folder'] == folder_path:
                        file_path = file_info['path']
                        break
        
        if file_path and os.path.exists(file_path):
            # 开始拖拽
            drag = QDrag(self.chat_area)
            mime_data = QMimeData()
            
            # 设置文件URL
            file_url = QUrl.fromLocalFile(file_path)
            mime_data.setUrls([file_url])
            
            # 执行拖拽
            drop_action = drag.exec(Qt.DropAction.CopyAction)
        else:
            # 调用原始的鼠标移动事件
            QTextEdit.mouseMoveEvent(self.chat_area, event)

    def clear_file_cache(self):
        """清理文件缓存"""
        import os
        import tempfile
        import shutil
        
        # 获取缓存目录路径
        temp_dir = tempfile.gettempdir()
        cache_dir = os.path.join(temp_dir, "cat_message_files")
        
        if not os.path.exists(cache_dir):
            QMessageBox.information(self, "清理缓存", "没有找到缓存文件，无需清理。")
            return
        
        # 确认对话框
        reply = QMessageBox.question(
            self, 
            "确认清理", 
            f"确定要清理所有缓存文件吗？\n\n缓存位置：{cache_dir}\n\n清理后将删除所有已下载的文件，此操作不可撤销。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                # 获取文件数量和总大小
                file_count = 0
                total_size = 0
                for root, dirs, files in os.walk(cache_dir):
                    file_count += len(files)
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            total_size += os.path.getsize(file_path)
                        except OSError:
                            pass
                
                # 删除缓存目录
                shutil.rmtree(cache_dir)
                
                # 清理本地文件路径记录
                self.file_paths.clear()
                
                # 格式化大小显示
                if total_size < 1024:
                    size_str = f"{total_size} B"
                elif total_size < 1024 * 1024:
                    size_str = f"{total_size // 1024} KB"
                else:
                    size_str = f"{total_size // (1024 * 1024)} MB"
                
                QMessageBox.information(
                    self, 
                    "清理完成", 
                    f"缓存清理完成！\n\n已删除 {file_count} 个文件\n释放空间：{size_str}"
                )
                
            except Exception as e:
                QMessageBox.warning(self, "清理失败", f"清理缓存时出错：{str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())