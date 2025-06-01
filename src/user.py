#python3
#user.py
#https://github.com/xhdndmm/cat-message

import sys
import socket
import json
import base64
import zlib
from datetime import datetime
from PyQt6.QtWidgets import  QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,QLineEdit, QPushButton, QTextEdit, QLabel, QMessageBox, QFileDialog, QComboBox, QToolButton, QMenu, QDialog, QProgressBar
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QUrl, QMimeData, QTimer
from PyQt6.QtGui import QAction, QTextCursor, QImage, QTextImageFormat, QDrag
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

REPO = "xhdndmm/cat-message"
CURRENT_VERSION = "v1.8" 

class RSACrypto:
    def __init__(self):
        self.key = None
        self.public_key = None
        self.private_key = None
        self.peer_public_key = None
        
    def generate_key_pair(self, key_size, progress_callback=None):
        """生成RSA密钥对，支持进度回调"""
        try:
            if progress_callback:
                progress_callback(f"正在生成{key_size}位RSA密钥...")
            
            # 使用更高效的随机数生成
            from Crypto.Random import get_random_bytes
            
            if progress_callback and key_size >= 4096:
                progress_callback(f"正在准备{key_size}位密钥生成（这可能需要几秒钟）...")
                
            self.key = RSA.generate(key_size)
            self.public_key = self.key.publickey()
            self.private_key = self.key
            
            if progress_callback:
                progress_callback(f"{key_size}位RSA密钥生成完成")
                
        except Exception as e:
            raise Exception(f"RSA密钥生成失败: {str(e)}")
        
    def export_public_key(self):
        """导出公钥"""
        return self.public_key.export_key()
        
    def import_peer_public_key(self, key_data):
        """导入对方公钥"""
        try:
            if not key_data:
                raise Exception("公钥数据为空")
            
            self.peer_public_key = RSA.import_key(key_data)
            
            # 验证导入的公钥
            if not self.peer_public_key.has_private():
                # 这是正确的，公钥不应该有私钥部分
                pass
            else:
                raise Exception("导入的数据包含私钥，安全风险")
                
        except ValueError as e:
            raise Exception(f"公钥格式无效: {str(e)}")
        except Exception as e:
            raise Exception(f"导入公钥失败: {str(e)}")
    
    def hybrid_encrypt(self, data):
        """混合加密：使用AES+RSA加密大数据"""
        try:
            if not self.peer_public_key:
                raise Exception("对方公钥未设置")
            
            if not data:
                raise Exception("加密数据为空")
            
            # 如果数据很小，直接使用RSA加密
            if len(data) <= 400:
                return self.encrypt(data)
            
            # 数据较大，使用混合加密
            # 1. 生成随机AES密钥（256位）
            aes_key = get_random_bytes(32)
            
            # 2. 使用AES加密数据
            cipher_aes = AES.new(aes_key, AES.MODE_CBC)
            padded_data = pad(data, AES.block_size)
            encrypted_data = cipher_aes.encrypt(padded_data)
            
            # 3. 使用RSA加密AES密钥
            cipher_rsa = PKCS1_OAEP.new(self.peer_public_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)
            
            # 4. 构造最终数据：标志 + RSA加密的AES密钥 + IV + AES加密的数据
            result = b"HYBRID" + len(encrypted_aes_key).to_bytes(2, 'big') + encrypted_aes_key + cipher_aes.iv + encrypted_data
            
            return result
            
        except Exception as e:
            raise Exception(f"混合加密失败: {str(e)}")
    
    def hybrid_decrypt(self, encrypted_data):
        """混合解密：解密AES+RSA加密的数据"""
        try:
            if not self.private_key:
                raise Exception("私钥未设置")
                
            if not encrypted_data:
                raise Exception("解密数据为空")
            
            # 检查是否为混合加密数据
            if not encrypted_data.startswith(b"HYBRID"):
                # 不是混合加密，使用传统RSA解密
                return self.decrypt(encrypted_data)
            
            # 是混合加密数据
            offset = 6  # "HYBRID"长度
            
            # 读取RSA加密的AES密钥长度
            aes_key_len = int.from_bytes(encrypted_data[offset:offset+2], 'big')
            offset += 2
            
            # 读取RSA加密的AES密钥
            encrypted_aes_key = encrypted_data[offset:offset+aes_key_len]
            offset += aes_key_len
            
            # 读取IV（16字节）
            iv = encrypted_data[offset:offset+16]
            offset += 16
            
            # 读取AES加密的数据
            aes_encrypted_data = encrypted_data[offset:]
            
            # 1. 使用RSA解密AES密钥
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)
            
            # 2. 使用AES密钥解密数据
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
            padded_data = cipher_aes.decrypt(aes_encrypted_data)
            
            # 3. 去除填充
            data = unpad(padded_data, AES.block_size)
            
            return data
            
        except Exception as e:
            raise Exception(f"混合解密失败: {str(e)}")
        
    def encrypt(self, data):
        """使用对方公钥加密数据（传统RSA加密，仅用于小数据）"""
        try:
            if not self.peer_public_key:
                raise Exception("对方公钥未设置")
            
            if not data:
                raise Exception("加密数据为空")
                
            if len(data) > 446:  # RSA PKCS1_OAEP 对于2048位密钥的最大数据长度
                raise Exception(f"数据过大，无法直接RSA加密: {len(data)} 字节")
                
            cipher = PKCS1_OAEP.new(self.peer_public_key)
            return cipher.encrypt(data)
            
        except Exception as e:
            raise Exception(f"加密失败: {str(e)}")
        
    def decrypt(self, encrypted_data):
        """使用自己的私钥解密数据（传统RSA解密）"""
        try:
            if not self.private_key:
                raise Exception("私钥未设置")
                
            if not encrypted_data:
                raise Exception("解密数据为空")
                
            cipher = PKCS1_OAEP.new(self.private_key)
            return cipher.decrypt(encrypted_data)
            
        except ValueError as e:
            raise Exception(f"解密失败，数据可能已损坏: {str(e)}")
        except Exception as e:
            raise Exception(f"解密失败: {str(e)}")

def send_message_with_length(sock, data_bytes):
    """发送带长度前缀的消息"""
    try:
        if not data_bytes:
            raise Exception("尝试发送空数据")
            
        length = len(data_bytes)
        if length > 5000 * 1024 * 1024:  # 50MB限制
            raise Exception(f"数据过大: {length} 字节")
        
        # 设置发送超时
        sock.settimeout(30)  # 30秒超时
        
        # 发送长度前缀
        length_bytes = length.to_bytes(4, byteorder='big')
        sock.sendall(length_bytes)
        
        # 发送数据
        sock.sendall(data_bytes)
        
        # 恢复socket超时设置
        sock.settimeout(None)
        
    except socket.timeout:
        raise Exception("网络发送超时，请检查网络连接")
    except ConnectionResetError:
        raise Exception("连接被对方重置，请检查服务器状态或重新连接")
    except ConnectionAbortedError:
        raise Exception("连接被本地软件中止，可能是防火墙或杀毒软件阻止了连接")
    except BrokenPipeError:
        raise Exception("连接管道已断开，服务器可能已关闭")
    except OSError as e:
        # 处理Windows特定错误
        if hasattr(e, 'winerror'):
            if e.winerror == 10053:
                raise Exception("连接被本地软件中止，请检查防火墙和杀毒软件设置")
            elif e.winerror == 10054:
                raise Exception("连接被对方强制关闭，服务器可能意外断开")
            elif e.winerror == 10060:
                raise Exception("连接超时，请检查网络连接或服务器地址")
            elif e.winerror == 10061:
                raise Exception("连接被拒绝，请确认服务器正在运行且端口正确")
            else:
                raise Exception(f"Windows网络错误 {e.winerror}: {str(e)}")
        else:
            raise Exception(f"网络发送错误: {str(e)}")
    except socket.error as e:
        raise Exception(f"网络发送错误: {str(e)}")
    except Exception as e:
        # 不在这里显示消息框，让调用方处理
        raise e

def read_message(sock):
    """读取网络消息"""
    try:
        # 设置较短的接收超时，避免无限等待
        sock.settimeout(30)  # 30秒超时
        
        # 读取消息长度
        raw_length = sock.recv(4)
        if not raw_length:
            return None
        if len(raw_length) != 4:
            raise Exception(f"消息长度字段不完整，收到 {len(raw_length)} 字节")
            
        msg_length = int.from_bytes(raw_length, byteorder='big')
        
        # 验证消息长度的合理性
        if msg_length <= 0:
            raise Exception(f"无效的消息长度: {msg_length}")
        if msg_length > 5000 * 1024 * 1024:  # 50MB限制
            raise Exception(f"消息长度过大: {msg_length} 字节")
        
        # 读取消息内容
        buffer = bytearray()
        while len(buffer) < msg_length:
            remaining = msg_length - len(buffer)
            chunk_size = min(4096, remaining)
            chunk = sock.recv(chunk_size)
            if not chunk:
                raise Exception(f"连接意外断开，已收到 {len(buffer)}/{msg_length} 字节")
            buffer.extend(chunk)
        
        # 恢复socket超时设置
        sock.settimeout(None)
        return buffer
        
    except socket.timeout:
        raise Exception("网络读取超时，请检查网络连接")
    except ConnectionResetError:
        raise Exception("连接被对方重置，请检查服务器状态")
    except ConnectionAbortedError:
        raise Exception("连接被本地软件中止，可能是防火墙或杀毒软件阻止了连接")
    except BrokenPipeError:
        raise Exception("连接管道已断开，服务器可能已关闭")
    except OSError as e:
        # 处理Windows特定错误
        if hasattr(e, 'winerror'):
            if e.winerror == 10053:
                raise Exception("连接被本地软件中止，请检查防火墙和杀毒软件设置")
            elif e.winerror == 10054:
                raise Exception("连接被对方强制关闭，服务器可能意外断开")
            elif e.winerror == 10060:
                raise Exception("连接超时，请检查网络连接或服务器地址")
            elif e.winerror == 10061:
                raise Exception("连接被拒绝，请确认服务器正在运行且端口正确")
            else:
                raise Exception(f"Windows网络错误 {e.winerror}: {str(e)}")
        else:
            raise Exception(f"网络读取错误: {str(e)}")
    except socket.error as e:
        raise Exception(f"网络读取错误: {str(e)}")
    except Exception as e:
        # 不在这里显示消息框，让调用方处理
        raise e

class ChatReceiver(QThread):
    """消息接收线程，处理网络通信"""
    new_message = pyqtSignal(str, str, object)  # text, msg_type, img_data
    update_online_users = pyqtSignal(int)
    connection_lost = pyqtSignal()  # 新增连接丢失信号
    
    def __init__(self, client_socket, crypto, main_window=None):
        super().__init__()
        self.client_socket = client_socket
        self.crypto = crypto  # 可能为None（无加密模式）
        self.running = True
        self.main_window = main_window  # 引用主窗口以获取图片服务器配置
        
    def run(self):
        while self.running:
            try:
                raw_data = read_message(self.client_socket)
                if not raw_data:
                    # 连接已断开
                    self.connection_lost.emit()
                    break
                    
                # 根据是否有加密决定处理方式
                if self.crypto:
                    # 使用混合解密消息
                    decrypted_data = self.crypto.hybrid_decrypt(raw_data)
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
                # 网络错误，发出连接丢失信号
                self.connection_lost.emit()
                break

    def get_image_server_url(self):
        """获取图片服务器URL"""
        if self.main_window:
            # 优先使用用户设置的图片服务器地址
            image_server = self.main_window.image_server_edit.text().strip()
            image_port = self.main_window.image_port_edit.text().strip()
            
            if image_server:
                # 用户指定了图片服务器地址
                if not image_port.isdigit():
                    image_port = "12346"  # 默认端口
                return f"http://{image_server}:{image_port}"
            else:
                # 使用聊天服务器地址
                chat_server = self.main_window.server_ip_edit.text().strip()
                if chat_server:
                    if not image_port.isdigit():
                        image_port = "12346"  # 默认端口
                    return f"http://{chat_server}:{image_port}"
        
        # 兜底方案：使用socket连接的对等地址
        try:
            server_ip = self.client_socket.getpeername()[0]
            return f"http://{server_ip}:12346"
        except:
            return None

    def process_message(self, data):
        """统一处理消息并发射信号"""
        msg_type = data.get("content_type", "text")
        if msg_type == "image":
            text = f"{data['username']} ({data.get('time', 'unknown')}) [图片]:"
            # 从服务器获取图片数据
            try:
                base_url = self.get_image_server_url()
                if not base_url:
                    QMessageBox.warning(None, "获取图片失败", "无法确定图片服务器地址")
                    return
                    
                image_url = f"{base_url}/image/{data['message']}"
                
                if self.main_window and self.main_window.debug_mode:
                    self.main_window.update_chat(f"🔍 调试: 正在从 {image_url} 下载图片")
                
                response = requests.get(image_url, timeout=10)
                if response.status_code == 200:
                    self.new_message.emit(text, "image", response.content)
                    if self.main_window and self.main_window.debug_mode:
                        self.main_window.update_chat(f"🔍 调试: 图片下载成功，大小: {len(response.content)} 字节")
                else:
                    error_msg = f"无法获取图片，服务器返回状态码: {response.status_code}"
                    if response.status_code == 404:
                        error_msg += "\n图片可能已被删除或不存在"
                    elif response.status_code == 500:
                        error_msg += "\n服务器内部错误"
                    
                    # 添加调试信息
                    if self.main_window and self.main_window.debug_mode:
                        error_msg += f"\n\n🔍 调试信息:\n请求URL: {image_url}"
                        
                    QMessageBox.warning(None, "获取图片失败", error_msg)
            except requests.exceptions.ConnectionError:
                base_url = self.get_image_server_url()
                error_msg = ("无法连接到图片服务器\n\n可能原因：\n"
                    "1. 图片服务器地址或端口配置错误\n"
                    "2. 服务器端口12346未开放\n"
                    "3. 图片/文件服务未正常启动\n"
                    "4. 防火墙阻止了连接\n\n"
                    f"当前图片服务器地址: {base_url}\n\n"
                    "解决方案：\n"
                    "1. 检查'图片服务器'设置是否正确\n"
                    "2. 联系服务器管理员确认端口12346状态\n"
                    "3. 尝试在'图片服务器'字段填入正确的公网地址")
                QMessageBox.warning(None, "获取图片失败", error_msg)
            except requests.exceptions.Timeout:
                QMessageBox.warning(None, "获取图片失败", "连接超时，请检查网络连接或图片服务器设置")
            except Exception as e:
                error_msg = f"获取图片时发生错误: {str(e)}"
                if self.main_window and self.main_window.debug_mode:
                    base_url = self.get_image_server_url()
                    error_msg += f"\n\n🔍 调试信息:\n图片服务器: {base_url}"
                QMessageBox.warning(None, "获取图片失败", error_msg)
        elif msg_type == "file":
            file_name = data.get("file_name", "未知文件")
            file_size = data.get("file_size", 0)
            text = f"{data['username']} ({data.get('time', 'unknown')}) [文件: {file_name}]:"
            
            # 下载文件到本地临时目录
            try:
                base_url = self.get_image_server_url()
                if not base_url:
                    self.new_message.emit(text, "file", {
                        "name": file_name, 
                        "size": file_size, 
                        "error": "无法确定文件服务器地址"
                    })
                    return
                    
                file_url = f"{base_url}/file/{data['message']}"
                response = requests.get(file_url, timeout=30)
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
                    error_msg = f"下载失败，状态码: {response.status_code}"
                    if response.status_code == 404:
                        error_msg = "文件不存在或已被删除"
                    elif response.status_code == 500:
                        error_msg = "服务器内部错误"
                    
                    self.new_message.emit(text, "file", {
                        "name": file_name, 
                        "size": file_size, 
                        "error": error_msg
                    })
            except requests.exceptions.ConnectionError:
                self.new_message.emit(text, "file", {
                    "name": file_name, 
                    "size": file_size, 
                    "error": "无法连接到文件服务器，请检查图片服务器设置和端口12346是否开放"
                })
            except requests.exceptions.Timeout:
                self.new_message.emit(text, "file", {
                    "name": file_name, 
                    "size": file_size, 
                    "error": "下载超时，文件可能过大或网络不稳定"
                })
            except Exception as e:
                self.new_message.emit(text, "file", {
                    "name": file_name, 
                    "size": file_size, 
                    "error": f"下载异常: {str(e)}"
                })
        else:
            text = f"{data['username']} ({data.get('time', 'unknown')}, {data.get('ip', 'unknown')}): {data['message']}"
            self.new_message.emit(text, "text", None)

    def stop(self):
        self.running = False
        self.quit()
        self.wait()

class AutoReconnectThread(QThread):
    """自动重连线程"""
    start_reconnect = pyqtSignal(int)  # 开始重连信号，参数为尝试次数
    reconnect_failed = pyqtSignal(str)  # 重连失败信号
    
    def __init__(self):
        super().__init__()
        self.running = True
        self.max_attempts = 5  # 最大重连次数
        self.retry_delay = 5   # 重连间隔（秒）
        
    def stop(self):
        """停止自动重连"""
        self.running = False
        
    def run(self):
        """自动重连逻辑 - 只负责延时和发送信号"""
        for attempt in range(1, self.max_attempts + 1):
            if not self.running:
                return
                
            # 发送开始重连信号
            self.start_reconnect.emit(attempt)
            
            # 等待连接结果（通过外部设置状态）
            # 等待最多30秒让连接完成
            for i in range(60):  # 30秒，每500ms检查一次
                if not self.running:
                    return
                self.msleep(500)
                
            # 如果这是最后一次尝试，等待下次重试
            if attempt < self.max_attempts and self.running:
                # 等待重试延迟
                for i in range(self.retry_delay * 2):  # 每500ms检查一次
                    if not self.running:
                        return
                    self.msleep(500)
                    
        # 所有重连尝试都失败了
        if self.running:
            self.reconnect_failed.emit(f"重连失败，已尝试{self.max_attempts}次")

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
        self._stop_flag = False
        
    def stop(self):
        """停止连接线程"""
        self._stop_flag = True
        self.running = False
        
    def run(self):
        client_socket = None
        max_retries = 2  # 最大重试次数
        retry_delay = 3  # 重试间隔（秒）
        
        for attempt in range(max_retries + 1):  # 总共尝试3次（首次+2次重试）
            try:
                if self._stop_flag:
                    return
                
                # 显示当前尝试状态
                if attempt == 0:
                    self.status_update.emit("正在连接服务器...")
                else:
                    self.status_update.emit(f"连接失败，正在重试 ({attempt}/{max_retries})...")
                    
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.settimeout(10)
                client_socket.connect((self.server_ip, self.server_port))
                client_socket.settimeout(None)
                
                if self._stop_flag:
                    client_socket.close()
                    return
                
                crypto = None
                
                # 根据加密模式处理
                if self.encryption_mode == "无加密":
                    try:
                        # 发送兼容性验证
                        verify_payload = {"command": "verify", "payload": "cat-message-v1.8-noenc"}
                        send_message_with_length(client_socket, json.dumps(verify_payload).encode('utf-8'))
                        
                        response = read_message(client_socket)
                        if not response or self._stop_flag:
                            if not self._stop_flag:
                                raise Exception("未收到服务器响应")
                            client_socket.close()
                            return
                        
                        # 安全的JSON解析
                        try:
                            response_data = json.loads(response.decode('utf-8'))
                        except (json.JSONDecodeError, UnicodeDecodeError) as e:
                            raise Exception(f"服务器响应格式错误: {str(e)}")
                        
                        if not (response_data.get("type") == "verify" and response_data.get("status") == "ok"):
                            error_msg = response_data.get('message', '未知错误') if isinstance(response_data, dict) else '服务器响应无效'
                            raise Exception(f"验证失败: {error_msg}")
                            
                    except Exception as e:
                        if client_socket:
                            try:
                                client_socket.close()
                            except:
                                pass
                        raise Exception(f"无加密模式验证失败: {str(e)}")
                        
                else:
                    try:
                        # 加密模式（AES+RSA2048）
                        if self.encryption_mode not in ["AES+RSA2048", "RSA2048"]:
                            raise Exception(f"不支持的加密模式: {self.encryption_mode}")
                            
                        key_size = 2048
                        client_socket.settimeout(30)  # RSA2048使用30秒超时
                        
                        # 在后台线程中生成密钥
                        crypto = RSACrypto()
                        
                        def progress_callback(message):
                            if not self._stop_flag:
                                self.status_update.emit(message)
                        
                        # 使用带进度回调的密钥生成
                        try:
                            crypto.generate_key_pair(key_size, progress_callback)
                        except Exception as e:
                            raise Exception(f"密钥生成失败: {str(e)}")
                        
                        if self._stop_flag:
                            client_socket.close()
                            return
                        
                        self.status_update.emit("正在验证服务器...")
                        
                        # 发送验证信息（使用RSA2048标识以保持兼容性）
                        try:
                            verify_payload = {"command": "verify", "payload": f"cat-message-v1.8-enc-{key_size}"}
                            send_message_with_length(client_socket, json.dumps(verify_payload).encode('utf-8'))
                        except Exception as e:
                            raise Exception(f"发送验证信息失败: {str(e)}")
                        
                        # 等待服务器响应
                        response = read_message(client_socket)
                        if not response or self._stop_flag:
                            if not self._stop_flag:
                                raise Exception("服务器验证响应超时或连接断开")
                            client_socket.close()
                            return
                        
                        # 安全的JSON解析
                        try:
                            response_data = json.loads(response.decode('utf-8'))
                        except (json.JSONDecodeError, UnicodeDecodeError) as e:
                            raise Exception(f"服务器验证响应格式错误: {str(e)}")
                        
                        if not isinstance(response_data, dict):
                            raise Exception("服务器验证响应格式无效")
                        
                        if not (response_data.get("type") == "verify" and response_data.get("status") == "ok"):
                            error_msg = response_data.get('message', '未知错误')
                            raise Exception(f"服务器验证失败: {error_msg}")
                        
                        # 检查公钥是否存在
                        if "public_key" not in response_data:
                            raise Exception("服务器未提供公钥")
                        
                        self.status_update.emit("正在交换密钥...")
                        
                        # 安全的密钥导入
                        try:
                            server_public_key_data = base64.b64decode(response_data["public_key"])
                            crypto.import_peer_public_key(server_public_key_data)
                        except Exception as e:
                            raise Exception(f"服务器公钥导入失败: {str(e)}")
                        
                        # 发送客户端公钥
                        try:
                            client_public_key = base64.b64encode(crypto.export_public_key()).decode('utf-8')
                            key_payload = {
                                "type": "public_key",
                                "public_key": client_public_key
                            }
                            send_message_with_length(client_socket, json.dumps(key_payload).encode('utf-8'))
                        except Exception as e:
                            raise Exception(f"发送客户端公钥失败: {str(e)}")
                            
                        # 恢复正常超时设置
                        client_socket.settimeout(None)
                            
                    except Exception as e:
                        if client_socket:
                            try:
                                client_socket.close()
                            except:
                                pass
                        raise Exception(f"AES+RSA2048加密模式验证失败: {str(e)}")
                
                # 连接成功
                if not self._stop_flag:
                    self.connection_success.emit(client_socket, crypto)
                    return  # 成功后直接返回，不再重试
                else:
                    if client_socket:
                        try:
                            client_socket.close()
                        except:
                            pass
                    return
                
            except socket.timeout:
                error_msg = "连接超时，请检查网络或服务器地址是否正确"
            except socket.gaierror as e:
                error_msg = f"域名解析失败，请检查服务器地址: {str(e)}"
            except ConnectionRefusedError:
                error_msg = "连接被拒绝，请检查服务器是否运行或端口是否正确"
            except Exception as e:
                error_msg = str(e)
                if "验证失败" in error_msg or "格式错误" in error_msg or "密钥" in error_msg:
                    error_msg = f"服务器验证错误:\n{error_msg}"
                else:
                    error_msg = f"连接服务器时发生错误:\n{error_msg}"
            
            # 如果不是最后一次尝试，则进行重试
            if attempt < max_retries and not self._stop_flag:
                self.status_update.emit(f"连接失败: {error_msg}")
                self.status_update.emit(f"{retry_delay}秒后进行第{attempt + 1}次重试...")
                
                # 等待重试延迟，但要检查停止标志
                for i in range(retry_delay):
                    if self._stop_flag:
                        return
                    import time
                    time.sleep(1)
                    if not self._stop_flag:
                        self.status_update.emit(f"{retry_delay - i - 1}秒后重试...")
            else:
                # 所有重试都失败了
                if not self._stop_flag:
                    if attempt > 0:
                        final_msg = f"连接失败，已重试{max_retries}次: {error_msg}"
                    else:
                        final_msg = error_msg
                    self.connection_error.emit(final_msg)
                break
                
        self.running = False

class MainWindow(QMainWindow):
    """主窗口类"""
    def __init__(self):
        super().__init__()
        self.setWindowOpacity(0.95)
        self.debug_mode = False  # 添加调试模式控制变量
        self.manual_disconnect = False  # 标记是否为手动断开
        self.auto_reconnect_enabled = True  # 自动重连开关
        self.last_connection_params = None  # 保存最后的连接参数
        self.reconnect_thread = None  # 自动重连线程
        self.init_ui()
        self.setup_toolbar()
        self.client_socket = None
        self.receiver_thread = None
        self.crypto = None
        self.file_paths = {}
        self.is_connected = False  # 添加连接状态标志

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
        self.encryption_mode_edit.addItems(["无加密", "AES+RSA2048"])
        self.encryption_mode_edit.setCurrentText("AES+RSA2048")  # 默认选择AES+RSA2048
        h_conn.addWidget(self.encryption_mode_edit)
        
        self.connect_btn = QPushButton("连接")
        self.connect_btn.clicked.connect(self.connect_to_server)
        h_conn.addWidget(self.connect_btn)
        
        # 图片服务器设置区域
        h_img_server = QHBoxLayout()
        h_img_server.addWidget(QLabel("图片服务器:"))
        self.image_server_edit = QLineEdit()
        self.image_server_edit.setPlaceholderText("留空自动使用聊天服务器地址")
        h_img_server.addWidget(self.image_server_edit)
        h_img_server.addWidget(QLabel("端口:"))
        self.image_port_edit = QLineEdit("12346")
        h_img_server.addWidget(self.image_port_edit)
        
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
        self.message_edit.returnPressed.connect(self.send_message)  # Enter键发送消息
        self.send_btn = QPushButton("发送")
        self.send_btn.clicked.connect(self.send_message)
        h_msg.addWidget(self.message_edit)
        h_msg.addWidget(self.send_btn)
        
        # 主布局
        v_layout = QVBoxLayout()
        v_layout.addLayout(h_conn)
        v_layout.addLayout(h_img_server)  # 添加图片服务器设置行
        v_layout.addWidget(self.chat_area)
        v_layout.addLayout(h_func)
        v_layout.addLayout(h_msg)
        central.setLayout(v_layout)
        
        # 设置初始UI状态（未连接）
        self.update_ui_connection_state(False)

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
        
        # 高级菜单
        advanced_button = QToolButton()
        advanced_button.setText("高级")
        advanced_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        
        advanced_menu = QMenu(advanced_button)
        
        # 调试信息开关
        self.debug_action = QAction("显示调试信息", self)
        self.debug_action.setCheckable(True)
        self.debug_action.setChecked(self.debug_mode)
        self.debug_action.triggered.connect(self.toggle_debug_mode)
        advanced_menu.addAction(self.debug_action)
        
        # 自动重连开关
        self.auto_reconnect_action = QAction("启用自动重连", self)
        self.auto_reconnect_action.setCheckable(True)
        self.auto_reconnect_action.setChecked(self.auto_reconnect_enabled)
        self.auto_reconnect_action.triggered.connect(self.toggle_auto_reconnect)
        advanced_menu.addAction(self.auto_reconnect_action)
        
        advanced_menu.addSeparator()  # 添加分隔线
        
        # 网络诊断工具
        network_diag_action = QAction("网络诊断", self)
        network_diag_action.triggered.connect(self.show_network_diagnostic)
        advanced_menu.addAction(network_diag_action)
        
        # 文件服务测试
        file_service_test_action = QAction("测试文件服务", self)
        file_service_test_action.triggered.connect(self.test_file_service)
        advanced_menu.addAction(file_service_test_action)
        
        # 连接日志
        connection_log_action = QAction("连接日志", self)
        connection_log_action.triggered.connect(self.show_connection_log)
        advanced_menu.addAction(connection_log_action)
        
        advanced_button.setMenu(advanced_menu)
        toolbar.addWidget(advanced_button)
        
        # 分隔符
        toolbar.addSeparator()
        
        # 关于按钮
        about_action = QAction("关于", self)
        about_action.triggered.connect(self.show_about)
        toolbar.addAction(about_action)
        
        # 在线人数显示
        self.online_users_label = QLabel("在线: 0")
        toolbar.addWidget(self.online_users_label)

    def send_file(self):
        """发送文件处理"""
        # 检查连接状态
        if not self.is_connection_ready():
            QMessageBox.warning(self, "警告", "未连接到服务器或连接已断开，请先连接服务器")
            return
            
        file_path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "All Files (*.*)")
        if not file_path:
            return
        
        import os
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        
        # 检查文件是否存在和可读
        try:
            with open(file_path, "rb") as f:
                # 只读取一小部分来验证文件可读性
                f.read(1024)
        except Exception as e:
            QMessageBox.warning(self, "文件错误", f"无法读取文件: {str(e)}")
            return
        
        # 创建进度对话框
        progress_dialog = FileSendProgressDialog(file_name, file_size, self)
        
        # 创建发送线程
        self.send_thread = FileSendThread(file_path, file_name, file_size, self)
        
        # 连接信号 - 使用lambda包装来传递额外参数
        self.send_thread.progress_updated.connect(
            lambda percentage, status, bytes_processed, elapsed_time: 
            progress_dialog.update_progress(percentage, status, bytes_processed, elapsed_time)
        )
        self.send_thread.send_completed.connect(
            lambda success, error_msg: self.on_file_send_completed(success, error_msg, file_name, file_size, progress_dialog)
        )
        
        # 连接取消信号
        progress_dialog.finished.connect(lambda: self.send_thread.cancel() if hasattr(self, 'send_thread') else None)
        
        # 启动发送
        self.send_thread.start()
        
        # 显示进度对话框
        result = progress_dialog.exec()
        
        # 如果用户取消了对话框，停止发送线程
        if result == QDialog.DialogCode.Rejected and hasattr(self, 'send_thread'):
            self.send_thread.cancel()
            self.send_thread.wait(1000)  # 等待最多1秒让线程停止
            
    def on_file_send_completed(self, success, error_msg, file_name, file_size, progress_dialog):
        """文件发送完成回调"""
        # 延迟关闭对话框，让用户看到"发送完成"状态
        QTimer.singleShot(1000, progress_dialog.accept)
        
        if success:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.append_message(f"You ({current_time}) [文件: {file_name}]:", "file", {"name": file_name, "size": file_size})
            if self.debug_mode:
                self.update_chat(f"🔍 调试: 文件发送成功")
        else:
            QMessageBox.warning(self, "发送失败", error_msg)

    def send_image(self):
        """发送图片处理"""
        # 检查连接状态
        if not self.is_connection_ready():
            QMessageBox.warning(self, "警告", "未连接到服务器或连接已断开，请先连接服务器")
            return
            
        file_path, _ = QFileDialog.getOpenFileName(self, "选择图片", "", "Images (*.png *.jpg *.jpeg *.gif *.bmp)")
        if not file_path:
            return
        
        # 检查图片文件是否可读
        try:
            with open(file_path, "rb") as f:
                # 只读取一小部分来验证文件可读性
                f.read(1024)
        except Exception as e:
            QMessageBox.warning(self, "图片错误", f"无法读取图片文件: {str(e)}")
            return
        
        import os
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        
        # 设置合理的文件大小限制检查
        if file_size > 5000 * 1024 * 1024:  # 限制5000MB
            file_size_mb = file_size / (1024 * 1024)
            QMessageBox.warning(self, "图片过大", 
                f"图片文件过大 ({file_size_mb:.2f} MB)\n\n"
                f"请选择小于5000MB的图片文件")
            return
        
        # 显示调试信息
        if self.debug_mode:
            if file_size < 1024:
                self.update_chat(f"🔍 调试: 准备发送图片，大小: {file_size} 字节")
            elif file_size < 1024 * 1024:
                file_size_kb = file_size / 1024
                self.update_chat(f"🔍 调试: 准备发送图片，大小: {file_size_kb:.1f} KB")
            else:
                file_size_mb = file_size / (1024 * 1024)
                self.update_chat(f"🔍 调试: 准备发送图片，大小: {file_size_mb:.2f} MB")
        
        # 创建进度对话框
        progress_dialog = FileSendProgressDialog(file_name, file_size, self)
        progress_dialog.setWindowTitle("发送图片")
        
        # 创建发送线程
        self.image_send_thread = ImageSendThread(file_path, self)
        
        # 连接信号 - 使用lambda包装来传递额外参数
        self.image_send_thread.progress_updated.connect(
            lambda percentage, status, bytes_processed, elapsed_time: 
            progress_dialog.update_progress(percentage, status, bytes_processed, elapsed_time)
        )
        self.image_send_thread.send_completed.connect(
            lambda success, error_msg, img_data: self.on_image_send_completed(success, error_msg, img_data, progress_dialog)
        )
        
        # 连接取消信号
        progress_dialog.finished.connect(lambda: self.image_send_thread.cancel() if hasattr(self, 'image_send_thread') else None)
        
        # 启动发送
        self.image_send_thread.start()
        
        # 显示进度对话框
        result = progress_dialog.exec()
        
        # 如果用户取消了对话框，停止发送线程
        if result == QDialog.DialogCode.Rejected and hasattr(self, 'image_send_thread'):
            self.image_send_thread.cancel()
            self.image_send_thread.wait(1000)  # 等待最多1秒让线程停止
            
    def on_image_send_completed(self, success, error_msg, img_data, progress_dialog):
        """图片发送完成回调"""
        # 延迟关闭对话框，让用户看到"发送完成"状态
        QTimer.singleShot(1000, progress_dialog.accept)
        
        if success:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.append_message(f"You ({current_time}) [图片]:", "image", img_data)
            if self.debug_mode:
                self.update_chat(f"🔍 调试: 图片发送成功")
            else:
                self.update_chat(f"✅ 图片发送成功")
        else:
            QMessageBox.warning(self, "发送失败", error_msg)
            if self.debug_mode:
                self.update_chat(f"🔍 调试: 图片发送失败: {error_msg}")

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
        
        # 保存连接参数以便自动重连
        self.last_connection_params = (server_ip, int(server_port), username, encryption_mode)
        self.manual_disconnect = False  # 标记为非手动断开
            
        # 禁用连接相关控件并显示连接状态
        self.connect_btn.setDisabled(True)
        self.server_ip_edit.setDisabled(True)
        self.server_port_edit.setDisabled(True)
        self.username_edit.setDisabled(True)
        self.encryption_mode_edit.setDisabled(True)
        self.connect_btn.setText("连接中...")
        
        # 创建连接线程
        self.connect_thread = ConnectThread(server_ip, int(server_port), username, encryption_mode)
        self.connect_thread.connection_success.connect(self.on_connection_success)
        self.connect_thread.connection_error.connect(self.on_connection_error)
        self.connect_thread.status_update.connect(self.on_status_update)
        self.connect_thread.start()

    def on_status_update(self, status):
        """更新连接状态"""
        # 简化状态显示逻辑
        if self.debug_mode:
            # 调试模式：显示详细信息
            self.connect_btn.setText(status)
            self.update_chat(f"🔍 调试: {status}")
        else:
            # 普通模式：只显示关键状态
            if any(keyword in status for keyword in ["连接中", "正在连接", "连接失败", "重试"]):
                self.connect_btn.setText("连接中...")
            elif "生成" in status and "密钥" in status:
                self.connect_btn.setText("生成密钥...")
            elif "验证" in status:
                self.connect_btn.setText("验证服务器...")
            elif "交换" in status and "密钥" in status:
                self.connect_btn.setText("交换密钥...")
            elif "完成" in status:
                self.connect_btn.setText("连接完成")
            else:
                # 其他状态保持当前显示
                pass

    def toggle_debug_mode(self):
        """切换调试模式"""
        self.debug_mode = not self.debug_mode
        self.debug_action.setChecked(self.debug_mode)
        
        if self.debug_mode:
            self.update_chat("🔧 调试模式已开启 - 将显示详细连接信息")
        else:
            self.update_chat("✅ 调试模式已关闭 - 将显示简化信息")

    def show_network_diagnostic(self):
        """显示网络诊断工具"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("网络诊断工具")
        dialog.setFixedSize(500, 400)
        
        layout = QVBoxLayout(dialog)
        
        # 诊断结果显示区域
        result_area = QTextEdit()
        result_area.setReadOnly(True)
        layout.addWidget(result_area)
        
        # 按钮区域
        button_layout = QHBoxLayout()
        
        ping_btn = QPushButton("Ping测试")
        ping_btn.clicked.connect(lambda: self.run_ping_test(result_area))
        button_layout.addWidget(ping_btn)
        
        port_btn = QPushButton("端口测试")
        port_btn.clicked.connect(lambda: self.run_port_test(result_area))
        button_layout.addWidget(port_btn)
        
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(dialog.close)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        dialog.exec()

    def show_connection_log(self):
        """显示连接日志"""
        QMessageBox.information(self, "连接日志", "连接日志功能正在开发中...")

    def run_ping_test(self, result_area):
        """运行Ping测试"""
        import subprocess
        import platform
        
        server_ip = self.server_ip_edit.text().strip()
        if not server_ip:
            result_area.append("❌ 请先输入服务器地址")
            return
            
        result_area.append(f"🔍 正在测试连接到 {server_ip}...")
        result_area.repaint()  # 立即更新显示
        
        try:
            # Windows和其他系统的ping命令参数不同
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "4", server_ip]
            else:
                cmd = ["ping", "-c", "4", server_ip]
                
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                result_area.append("✅ Ping测试成功")
                result_area.append(result.stdout)
            else:
                result_area.append("❌ Ping测试失败")
                result_area.append(result.stderr)
                
        except subprocess.TimeoutExpired:
            result_area.append("⏰ Ping测试超时")
        except Exception as e:
            result_area.append(f"❌ Ping测试出错: {str(e)}")

    def run_port_test(self, result_area):
        """运行端口测试"""
        import socket
        
        server_ip = self.server_ip_edit.text().strip()
        server_port = self.server_port_edit.text().strip()
        
        if not server_ip or not server_port:
            result_area.append("❌ 请先输入服务器地址和端口")
            return
            
        if not server_port.isdigit():
            result_area.append("❌ 端口号必须是数字")
            return
            
        port = int(server_port)
        result_area.append(f"🔍 正在测试端口 {server_ip}:{port}...")
        result_area.repaint()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((server_ip, port))
            sock.close()
            
            if result == 0:
                result_area.append("✅ 端口12346连接成功")
            else:
                result_area.append("❌ 端口12346连接失败")
                
        except Exception as e:
            result_area.append(f"❌ 端口测试出错: {str(e)}")

    def on_connection_success(self, client_socket, crypto):
        """连接成功回调"""
        self.client_socket = client_socket
        self.crypto = crypto
        
        # 更新UI状态
        self.update_ui_connection_state(True)
        
        # 显示连接成功信息
        encryption_info = "无加密" if not crypto else f"AES+RSA2048混合加密"
        self.update_chat(f"✅ 成功连接到服务器 ({encryption_info})")
        
        # 启动消息接收线程
        self.receiver_thread = ChatReceiver(self.client_socket, self.crypto, self)
        self.receiver_thread.new_message.connect(self.update_chat)
        self.receiver_thread.update_online_users.connect(self.update_online_users)
        self.receiver_thread.connection_lost.connect(self.on_connection_lost)
        self.receiver_thread.start()
        
    def on_connection_error(self, error_msg):
        """连接失败回调"""
        # 更新UI状态
        self.update_ui_connection_state(False)
        
        # 在聊天区域显示错误信息
        self.update_chat(f"❌ 连接失败: {error_msg}")
        
        # 显示错误对话框
        QMessageBox.critical(self, "连接失败", error_msg)

    def send_message(self):
        """发送文本消息"""
        # 检查连接状态
        if not self.is_connection_ready():
            QMessageBox.warning(self, "警告", "未连接到服务器或连接已断开，请先连接服务器")
            return
        
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
        
        if self.send_payload(payload):
            self.append_message(f"You ({current_time}): {message}", "text")
            self.message_edit.clear()
        else:
            QMessageBox.warning(self, "发送失败", "消息发送失败，请检查网络连接")

    def send_payload(self, payload):
        """发送消息通用方法"""
        try:
            # 检查连接状态
            if not self.client_socket:
                return False
                
            # 检查socket是否仍然有效
            try:
                # 尝试获取对等方地址来检查连接是否有效
                self.client_socket.getpeername()
            except (OSError, socket.error):
                # 连接已断开
                self.client_socket = None
                return False
            
            json_data = json.dumps(payload).encode('utf-8')
            
            if self.crypto:
                # 使用混合加密模式
                if self.debug_mode:
                    data_size = len(json_data)
                    self.update_chat(f"🔍 调试: 准备加密数据，大小: {data_size} 字节")
                
                encrypted_data = self.crypto.hybrid_encrypt(json_data)
                
                if self.debug_mode:
                    encrypted_size = len(encrypted_data)
                    self.update_chat(f"🔍 调试: 数据加密完成，加密后大小: {encrypted_size} 字节")
                
                send_message_with_length(self.client_socket, encrypted_data)
            else:
                # 无加密模式
                send_message_with_length(self.client_socket, json_data)
            return True
            
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
            # 连接被重置或中断
            self.client_socket = None
            return False
        except Exception as e:
            # 其他错误
            if self.debug_mode:
                self.update_chat(f"🔍 调试: 发送失败: {str(e)}")
            return False

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
        """加载聊天历史"""
        if not self.is_connection_ready():
            QMessageBox.warning(self, "警告", "未连接到服务器或连接已断开，请先连接服务器")
            return
            
        self.chat_area.clear()
        try:
            payload = {"command": "load_history"}
            success = self.send_payload(payload)
            if not success:
                # 发送失败，可能连接已断开
                if self.debug_mode:
                    self.update_chat("🔍 调试: 加载历史记录请求发送失败，可能连接已断开")
                # 触发连接丢失处理，这将启动自动重连
                self.on_connection_lost()
        except Exception as e:
            if self.debug_mode:
                self.update_chat(f"🔍 调试: 加载历史记录异常: {str(e)}")
            QMessageBox.warning(self, "加载错误", f"加载聊天记录失败: {str(e)}")
            # 如果是网络相关异常，也触发连接丢失处理
            if any(keyword in str(e).lower() for keyword in ["connection", "socket", "network", "连接"]):
                self.on_connection_lost()

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
        """断开与服务器的连接"""
        # 标记为手动断开
        self.manual_disconnect = True
        
        # 停止自动重连线程
        if self.reconnect_thread and self.reconnect_thread.isRunning():
            self.reconnect_thread.stop()
            self.reconnect_thread.wait(1000)
        
        # 停止连接线程（如果正在运行）
        if hasattr(self, 'connect_thread') and self.connect_thread and self.connect_thread.isRunning():
            self.connect_thread.stop()
            
        # 关闭socket连接
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.client_socket.close()
            except Exception:
                pass
                
        # 停止接收线程
        if self.receiver_thread:
            try:
                self.receiver_thread.running = False
                self.receiver_thread.quit()
                # 短暂等待，避免卡死
                if not self.receiver_thread.wait(300):
                    self.receiver_thread.terminate()
            except Exception:
                pass
                
        # 更新UI状态
        self.update_ui_connection_state(False)
        
        # 更新聊天区域
        self.update_chat("已手动断开与服务器的连接。")

    def show_about(self):
        QMessageBox.information(self, "关于", '<a href="https://github.com/xhdndmm/cat-message">cat-message-user-v1.8</a><br><a href="https://docs.cat-message.xhdndmm.cn">使用文档</a>')
        
    def closeEvent(self, event):
        """程序关闭事件"""
        # 标记为手动断开
        self.manual_disconnect = True
        
        # 停止自动重连线程
        if self.reconnect_thread and self.reconnect_thread.isRunning():
            self.reconnect_thread.stop()
            self.reconnect_thread.wait(1000)
        
        # 停止连接线程（如果正在运行）
        if hasattr(self, 'connect_thread') and self.connect_thread and self.connect_thread.isRunning():
            self.connect_thread.stop()
            
        # 停止文件发送线程
        if hasattr(self, 'send_thread') and self.send_thread and self.send_thread.isRunning():
            self.send_thread.cancel()
            self.send_thread.wait(1000)
            
        # 停止图片发送线程
        if hasattr(self, 'image_send_thread') and self.image_send_thread and self.image_send_thread.isRunning():
            self.image_send_thread.cancel()
            self.image_send_thread.wait(1000)
            
        # 关闭socket连接
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.client_socket.close()
            except Exception:
                pass
                
        # 停止接收线程
        if self.receiver_thread:
            try:
                self.receiver_thread.running = False
                self.receiver_thread.quit()
                # 短暂等待，避免卡死
                if not self.receiver_thread.wait(300):
                    self.receiver_thread.terminate()
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

    def is_connection_ready(self):
        """检查连接是否就绪"""
        # 检查是否有socket连接
        if not self.client_socket:
            return False
            
        # 检查是否正在连接中
        if hasattr(self, 'connect_thread') and self.connect_thread and self.connect_thread.isRunning():
            return False
            
        # 检查socket是否仍然有效
        try:
            self.client_socket.getpeername()
            return True
        except (OSError, socket.error):
            # 连接已断开，清理状态
            self.client_socket = None
            self.is_connected = False
            self.update_ui_connection_state(False)
            return False
            
    def update_ui_connection_state(self, connected):
        """更新UI控件的连接状态"""
        self.is_connected = connected
        
        if connected:
            # 连接成功状态
            self.connect_btn.setText("已连接")
            self.connect_btn.setDisabled(True)
            self.server_ip_edit.setDisabled(True)
            self.server_port_edit.setDisabled(True)
            self.username_edit.setDisabled(True)
            self.encryption_mode_edit.setDisabled(True)
            # 图片服务器设置在连接后仍可修改（用于公网部署调试）
            self.image_server_edit.setDisabled(False)
            self.image_port_edit.setDisabled(False)
            
            # 启用功能按钮
            self.send_btn.setDisabled(False)
            self.btn_upload.setDisabled(False)
            self.btn_send_file.setDisabled(False)
            self.load_history_btn.setDisabled(False)
            self.disconnect_btn.setDisabled(False)
            self.message_edit.setDisabled(False)
        else:
            # 断开连接状态
            self.connect_btn.setText("连接")
            self.connect_btn.setDisabled(False)
            self.server_ip_edit.setDisabled(False)
            self.server_port_edit.setDisabled(False)
            self.username_edit.setDisabled(False)
            self.encryption_mode_edit.setDisabled(False)
            self.image_server_edit.setDisabled(False)
            self.image_port_edit.setDisabled(False)
            
            # 禁用功能按钮
            self.send_btn.setDisabled(True)
            self.btn_upload.setDisabled(True)
            self.btn_send_file.setDisabled(True)
            self.load_history_btn.setDisabled(True)
            self.disconnect_btn.setDisabled(True)
            self.message_edit.setDisabled(True)

    def on_connection_lost(self):
        """连接丢失处理"""
        # 清理连接状态
        self.client_socket = None
        self.crypto = None
        if self.receiver_thread:
            self.receiver_thread.running = False
            self.receiver_thread = None
            
        # 更新UI状态
        self.update_ui_connection_state(False)
        
        # 检查是否为手动断开
        if self.manual_disconnect:
            # 手动断开，不进行自动重连
            if self.debug_mode:
                self.update_chat("🔍 调试: 手动断开连接，不进行自动重连")
            return
            
        # 意外断开，显示提示信息
        self.update_chat("⚠️ 与服务器的连接意外断开")
        
        # 如果启用了自动重连且有保存的连接参数
        if self.auto_reconnect_enabled and self.last_connection_params:
            self.update_chat("🔄 正在准备自动重连...")
            self.start_auto_reconnect()
        else:
            QMessageBox.warning(self, "连接断开", "与服务器的连接已断开，请重新连接")
            
    def start_auto_reconnect(self):
        """启动自动重连"""
        # 如果已有重连线程在运行，先停止
        if self.reconnect_thread and self.reconnect_thread.isRunning():
            self.reconnect_thread.stop()
            self.reconnect_thread.wait(1000)
            
        # 创建新的重连线程
        self.reconnect_thread = AutoReconnectThread()
        self.reconnect_thread.start_reconnect.connect(self.on_reconnect_attempt)
        self.reconnect_thread.reconnect_failed.connect(self.on_reconnect_failed)
        
    def on_reconnect_attempt(self, attempt):
        """重连尝试回调"""
        self.update_chat(f"🔄 正在进行第{attempt}次重连尝试...")
        self.connect_btn.setText(f"重连中({attempt}/5)...")
        
    def on_reconnect_failed(self, error_msg):
        """重连失败回调"""
        self.update_chat(f"❌ 自动重连失败: {error_msg}")
        QMessageBox.warning(self, "自动重连失败", f"自动重连失败:\n{error_msg}\n\n请手动重新连接")
        
    def toggle_auto_reconnect(self):
        """切换自动重连开关"""
        self.auto_reconnect_enabled = not self.auto_reconnect_enabled
        self.auto_reconnect_action.setChecked(self.auto_reconnect_enabled)
        
        if self.auto_reconnect_enabled:
            self.update_chat("✅ 自动重连已启用")
        else:
            self.update_chat("❌ 自动重连已禁用")

    def test_file_service(self):
        """测试文件服务"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("文件服务测试")
        dialog.setFixedSize(600, 500)
        
        layout = QVBoxLayout(dialog)
        
        # 测试结果显示区域
        result_area = QTextEdit()
        result_area.setReadOnly(True)
        layout.addWidget(result_area)
        
        # 按钮区域
        button_layout = QHBoxLayout()
        
        port_test_btn = QPushButton("测试12346端口")
        port_test_btn.clicked.connect(lambda: self.test_file_service_port(result_area))
        button_layout.addWidget(port_test_btn)
        
        http_test_btn = QPushButton("测试HTTP服务")
        http_test_btn.clicked.connect(lambda: self.test_http_service(result_area))
        button_layout.addWidget(http_test_btn)
        
        send_test_btn = QPushButton("发送测试图片")
        send_test_btn.clicked.connect(lambda: self.send_test_image(result_area))
        button_layout.addWidget(send_test_btn)
        
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(dialog.close)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        dialog.exec()
        
    def test_file_service_port(self, result_area):
        """测试文件服务端口12346"""
        # 获取图片服务器配置
        image_server = self.image_server_edit.text().strip()
        image_port = self.image_port_edit.text().strip()
        
        if image_server:
            # 使用用户指定的图片服务器地址
            server_ip = image_server
            if not image_port.isdigit():
                image_port = "12346"
            port = int(image_port)
        elif self.is_connection_ready():
            # 使用聊天服务器地址
            server_ip = self.server_ip_edit.text().strip()
            if not image_port.isdigit():
                image_port = "12346"
            port = int(image_port)
        else:
            result_area.append("❌ 请先连接到服务器或配置图片服务器地址")
            return
            
        try:
            result_area.append(f"🔍 正在测试文件服务端口 {server_ip}:{port}...")
            result_area.repaint()
            
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((server_ip, port))
            sock.close()
            
            if result == 0:
                result_area.append(f"✅ 端口{port}连接成功")
            else:
                result_area.append(f"❌ 端口{port}连接失败")
                result_area.append("⚠️ 可能原因：")
                result_area.append("   1. 服务器未启动文件服务")
                result_area.append(f"   2. 防火墙阻止了端口{port}")
                result_area.append("   3. 服务器配置问题")
                result_area.append("   4. 图片服务器地址配置错误")
                
        except Exception as e:
            result_area.append(f"❌ 端口测试异常: {str(e)}")
            
    def test_http_service(self, result_area):
        """测试HTTP文件服务"""
        # 获取图片服务器配置
        image_server = self.image_server_edit.text().strip()
        image_port = self.image_port_edit.text().strip()
        
        if image_server:
            # 使用用户指定的图片服务器地址
            server_ip = image_server
            if not image_port.isdigit():
                image_port = "12346"
            base_url = f"http://{server_ip}:{image_port}"
        elif self.is_connection_ready():
            # 使用聊天服务器地址
            server_ip = self.server_ip_edit.text().strip()
            if not image_port.isdigit():
                image_port = "12346"
            base_url = f"http://{server_ip}:{image_port}"
        else:
            result_area.append("❌ 请先连接到服务器或配置图片服务器地址")
            return
            
        try:
            result_area.append(f"🔍 正在测试HTTP文件服务 {base_url}...")
            result_area.repaint()
            
            import requests
            # 测试一个不存在的文件，应该返回404
            test_url = f"{base_url}/file/test-non-exist"
            response = requests.get(test_url, timeout=10)
            
            if response.status_code == 404:
                result_area.append("✅ HTTP文件服务正常运行")
                result_area.append("   服务器正确返回404状态码")
            else:
                result_area.append(f"⚠️ HTTP服务响应异常，状态码: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            result_area.append("❌ 无法连接到HTTP文件服务")
            result_area.append("⚠️ 可能原因：")
            result_area.append("   1. 文件服务未启动")
            result_area.append(f"   2. 端口{image_port}被阻止")
            result_area.append("   3. 服务器配置错误")
            result_area.append("   4. 图片服务器地址配置错误")
            result_area.append(f"\n当前测试地址: {base_url}")
        except requests.exceptions.Timeout:
            result_area.append("❌ HTTP服务连接超时")
        except Exception as e:
            result_area.append(f"❌ HTTP测试异常: {str(e)}")
            
    def send_test_image(self, result_area):
        """发送测试图片"""
        if not self.is_connection_ready():
            result_area.append("❌ 请先连接到服务器")
            return
            
        result_area.append("🔍 正在发送测试图片...")
        result_area.repaint()
        
        try:
            # 创建一个简单的测试图片（1x1像素的PNG）
            import base64
            # 这是一个1x1像素的透明PNG图片的base64编码
            test_png_data = base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=="
            )
            
            # 构建消息
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            payload = {
                "username": self.username_edit.text().strip(),
                "message": base64.b64encode(test_png_data).decode('utf-8'),
                "time": current_time,
                "content_type": "image"
            }
            
            if self.send_payload(payload):
                result_area.append("✅ 测试图片发送成功")
                result_area.append("📝 请检查聊天界面是否显示图片")
                # 也在聊天界面显示
                self.append_message(f"🧪 测试图片 ({current_time}):", "image", test_png_data)
            else:
                result_area.append("❌ 测试图片发送失败")
                result_area.append("⚠️ 请检查网络连接和服务器状态")
                
        except Exception as e:
            result_area.append(f"❌ 发送测试图片异常: {str(e)}")

class FileSendProgressDialog(QDialog):
    """文件发送进度对话框"""
    def __init__(self, file_name, file_size, parent=None):
        super().__init__(parent)
        self.file_name = file_name
        self.file_size = file_size
        self.cancelled = False
        self.start_time = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("发送文件")
        self.setFixedSize(450, 200)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        
        # 文件信息
        info_label = QLabel(f"正在发送: {self.file_name}")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        size_label = QLabel(f"大小: {self.format_file_size(self.file_size)}")
        layout.addWidget(size_label)
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setFormat("%v% (%p%)")  # 显示百分比和值
        layout.addWidget(self.progress_bar)
        
        # 详细进度信息
        progress_info_layout = QHBoxLayout()
        
        # 传输速度
        self.speed_label = QLabel("速度: 计算中...")
        progress_info_layout.addWidget(self.speed_label)
        
        # 剩余时间
        self.time_label = QLabel("剩余: 计算中...")
        progress_info_layout.addWidget(self.time_label)
        
        layout.addLayout(progress_info_layout)
        
        # 状态标签
        self.status_label = QLabel("准备发送...")
        layout.addWidget(self.status_label)
        
        # 按钮
        button_layout = QHBoxLayout()
        self.cancel_btn = QPushButton("取消")
        self.cancel_btn.clicked.connect(self.cancel_send)
        button_layout.addWidget(self.cancel_btn)
        layout.addLayout(button_layout)
        
    def format_file_size(self, size):
        """格式化文件大小"""
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.1f} GB"
            
    def format_speed(self, bytes_per_second):
        """格式化传输速度"""
        if bytes_per_second < 1024:
            return f"{bytes_per_second:.1f} B/s"
        elif bytes_per_second < 1024 * 1024:
            return f"{bytes_per_second / 1024:.1f} KB/s"
        elif bytes_per_second < 1024 * 1024 * 1024:
            return f"{bytes_per_second / (1024 * 1024):.1f} MB/s"
        else:
            return f"{bytes_per_second / (1024 * 1024 * 1024):.1f} GB/s"
            
    def format_time(self, seconds):
        """格式化时间"""
        if seconds < 60:
            return f"{int(seconds)}秒"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{minutes}分{secs}秒"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}时{minutes}分"
            
    def update_progress(self, percentage, status="", bytes_processed=0, elapsed_time=0):
        """更新进度"""
        import time
        
        if self.start_time is None:
            self.start_time = time.time()
            
        self.progress_bar.setValue(int(percentage))
        
        if status:
            self.status_label.setText(status)
            
        # 计算传输速度和剩余时间
        if elapsed_time > 0 and bytes_processed > 0:
            speed = bytes_processed / elapsed_time  # 字节/秒
            self.speed_label.setText(f"速度: {self.format_speed(speed)}")
            
            # 计算剩余时间
            if percentage > 0 and percentage < 100:
                remaining_bytes = self.file_size - bytes_processed
                if speed > 0:
                    remaining_time = remaining_bytes / speed
                    self.time_label.setText(f"剩余: {self.format_time(remaining_time)}")
                else:
                    self.time_label.setText("剩余: 计算中...")
            elif percentage >= 100:
                self.time_label.setText("剩余: 完成")
        elif percentage >= 100:
            self.speed_label.setText("速度: 完成")
            self.time_label.setText("剩余: 完成")
            
    def cancel_send(self):
        """取消发送"""
        self.cancelled = True
        self.reject()
        
    def closeEvent(self, event):
        """关闭事件"""
        self.cancelled = True
        event.accept()

class FileSendThread(QThread):
    """文件发送线程"""
    progress_updated = pyqtSignal(float, str, int, float)  # 进度百分比, 状态信息, 已处理字节数, 已用时间
    send_completed = pyqtSignal(bool, str)  # 成功/失败, 错误信息
    
    def __init__(self, file_path, file_name, file_size, main_window):
        super().__init__()
        self.file_path = file_path
        self.file_name = file_name
        self.file_size = file_size
        self.main_window = main_window
        self.cancelled = False
        
    def cancel(self):
        """取消发送"""
        self.cancelled = True
        
    def run(self):
        import time
        
        start_time = time.time()
        
        try:
            # 阶段1: 读取文件 (0-30%)
            self.progress_updated.emit(0, "正在读取文件...", 0, 0)
            
            if self.cancelled:
                return
                
            # 分块读取文件以显示进度
            chunk_size = 32 * 1024  # 32KB块，更小的块以提供更平滑的进度
            file_data = bytearray()
            
            with open(self.file_path, "rb") as f:
                bytes_read = 0
                last_update_time = start_time
                
                while True:
                    if self.cancelled:
                        return
                        
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                        
                    file_data.extend(chunk)
                    bytes_read += len(chunk)
                    
                    current_time = time.time()
                    elapsed = current_time - start_time
                    
                    # 每100ms或每MB更新一次进度
                    if (current_time - last_update_time) >= 0.1 or bytes_read % (1024 * 1024) == 0:
                        read_progress = (bytes_read / self.file_size) * 30
                        self.progress_updated.emit(
                            read_progress, 
                            f"读取中... ({self.format_bytes(bytes_read)}/{self.format_bytes(self.file_size)})",
                            bytes_read,
                            elapsed
                        )
                        last_update_time = current_time
            
            if self.cancelled:
                return
            
            # 阶段2: Base64编码 (30-60%)
            current_time = time.time()
            elapsed = current_time - start_time
            self.progress_updated.emit(30, "正在编码文件...", bytes_read, elapsed)
            
            # 分块编码以显示进度和避免内存问题
            encoded_chunks = []
            total_chunks = (len(file_data) + chunk_size - 1) // chunk_size
            encoded_bytes = 0
            
            for i in range(0, len(file_data), chunk_size):
                if self.cancelled:
                    return
                    
                chunk = file_data[i:i + chunk_size]
                encoded_chunk = base64.b64encode(chunk).decode('utf-8')
                encoded_chunks.append(encoded_chunk)
                encoded_bytes += len(encoded_chunk)
                
                current_time = time.time()
                elapsed = current_time - start_time
                
                # 编码进度 30-60%
                encode_progress = 30 + ((i // chunk_size + 1) / total_chunks) * 30
                self.progress_updated.emit(
                    encode_progress, 
                    f"编码中... ({i // chunk_size + 1}/{total_chunks} 块)",
                    bytes_read + encoded_bytes // 4,  # 粗略估算编码对应的原始字节数
                    elapsed
                )
                
                # 短暂休眠避免CPU占用过高
                self.msleep(1)
            
            if self.cancelled:
                return
                
            encoded_data = ''.join(encoded_chunks)
            
            # 阶段3: 构建消息 (60-70%)
            current_time = time.time()
            elapsed = current_time - start_time
            self.progress_updated.emit(60, "构建消息...", bytes_read, elapsed)
            
            current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            payload = {
                "username": self.main_window.username_edit.text().strip(),
                "message": encoded_data,
                "time": current_datetime,
                "content_type": "file",
                "file_name": self.file_name,
                "file_size": self.file_size
            }
            
            if self.cancelled:
                return
            
            # 阶段4: 发送数据 (70-100%)
            current_time = time.time()
            elapsed = current_time - start_time
            self.progress_updated.emit(70, "正在发送到服务器...", bytes_read, elapsed)
            
            success = self.main_window.send_payload(payload)
            
            if self.cancelled:
                return
            
            final_time = time.time()
            total_elapsed = final_time - start_time
            
            if success:
                self.progress_updated.emit(100, "发送完成!", self.file_size, total_elapsed)
                self.send_completed.emit(True, "")
            else:
                self.send_completed.emit(False, "发送失败，请检查网络连接")
                
        except Exception as e:
            if not self.cancelled:
                self.send_completed.emit(False, f"发送异常: {str(e)}")
                
    def format_bytes(self, size):
        """格式化字节数显示"""
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.1f} GB"

class ImageSendThread(QThread):
    """图片发送线程"""
    progress_updated = pyqtSignal(float, str, int, float)  # 进度百分比, 状态信息, 已处理字节数, 已用时间
    send_completed = pyqtSignal(bool, str, object)  # 成功/失败, 错误信息, 图片数据
    
    def __init__(self, file_path, main_window):
        super().__init__()
        self.file_path = file_path
        self.main_window = main_window
        self.cancelled = False
        
    def cancel(self):
        """取消发送"""
        self.cancelled = True
        
    def run(self):
        import time
        import os
        
        start_time = time.time()
        
        try:
            # 阶段1: 读取图片 (0-30%)
            self.progress_updated.emit(0, "正在读取图片...", 0, 0)
            
            if self.cancelled:
                return
                
            file_size = os.path.getsize(self.file_path)
            
            with open(self.file_path, "rb") as f:
                img_data = f.read()
            
            if self.cancelled:
                return
            
            current_time = time.time()
            elapsed = current_time - start_time
            self.progress_updated.emit(30, "图片读取完成", file_size, elapsed)
            
            # 检查文件大小
            file_size_mb = file_size / (1024 * 1024)
            
            if file_size > 5000 * 1024 * 1024:  # 限制5000MB
                self.send_completed.emit(False, f"图片文件过大 ({file_size_mb:.2f} MB)，请选择小于5000MB的图片文件", None)
                return
            
            # 阶段2: Base64编码 (30-70%)
            current_time = time.time()
            elapsed = current_time - start_time
            self.progress_updated.emit(30, "正在编码图片...", file_size, elapsed)
            
            try:
                # 对于大图片，分块编码
                if file_size > 1024 * 1024:  # 大于1MB的图片分块编码
                    chunk_size = 64 * 1024  # 64KB块
                    encoded_chunks = []
                    total_chunks = (len(img_data) + chunk_size - 1) // chunk_size
                    
                    for i in range(0, len(img_data), chunk_size):
                        if self.cancelled:
                            return
                            
                        chunk = img_data[i:i + chunk_size]
                        encoded_chunk = base64.b64encode(chunk).decode('utf-8')
                        encoded_chunks.append(encoded_chunk)
                        
                        current_time = time.time()
                        elapsed = current_time - start_time
                        
                        # 编码进度 30-70%
                        encode_progress = 30 + ((i // chunk_size + 1) / total_chunks) * 40
                        self.progress_updated.emit(
                            encode_progress, 
                            f"编码中... ({i // chunk_size + 1}/{total_chunks} 块)",
                            file_size,
                            elapsed
                        )
                        
                        # 短暂休眠避免CPU占用过高
                        self.msleep(1)
                    
                    encoded_data = ''.join(encoded_chunks)
                else:
                    # 小图片直接编码
                    encoded_data = base64.b64encode(img_data).decode('utf-8')
                    current_time = time.time()
                    elapsed = current_time - start_time
                    self.progress_updated.emit(70, "编码完成", file_size, elapsed)
                    
            except Exception as e:
                self.send_completed.emit(False, f"图片数据编码失败: {str(e)}", None)
                return
            
            if self.cancelled:
                return
            
            # 阶段3: 构建消息 (70-80%)
            current_time = time.time()
            elapsed = current_time - start_time
            self.progress_updated.emit(70, "构建消息...", file_size, elapsed)
            
            current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            payload = {
                "username": self.main_window.username_edit.text().strip(),
                "message": encoded_data,
                "time": current_datetime,
                "content_type": "image"
            }
            
            if self.cancelled:
                return
            
            # 阶段4: 发送数据 (80-100%)
            current_time = time.time()
            elapsed = current_time - start_time
            self.progress_updated.emit(80, "正在发送到服务器...", file_size, elapsed)
            
            success = self.main_window.send_payload(payload)
            
            if self.cancelled:
                return
            
            final_time = time.time()
            total_elapsed = final_time - start_time
            
            if success:
                self.progress_updated.emit(100, "发送完成!", file_size, total_elapsed)
                self.send_completed.emit(True, "", img_data)
            else:
                error_msg = "图片发送失败"
                if self.main_window.crypto:
                    error_msg += f"\n\n📊 图片信息：\n大小：{file_size} 字节"
                    error_msg += "\n\n❌ RSA加密限制：\n图片太大，无法通过RSA加密发送"
                    error_msg += "\n\n💡 解决方案：\n1. 断开连接并选择'无加密'模式\n2. 或选择更小的图片"
                else:
                    error_msg += "\n\n可能原因：\n1. 网络连接问题\n2. 服务器错误\n3. 图片格式问题"
                self.send_completed.emit(False, error_msg, None)
                
        except Exception as e:
            if not self.cancelled:
                self.send_completed.emit(False, f"发送图片时发生异常: {str(e)}", None)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())