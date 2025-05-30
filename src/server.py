#python3
#server.py
#https://github.com/xhdndmm/cat-message

print("cat-message-server-v1.6")

import socket
import threading
import json
import os
import base64
from datetime import datetime
import logging
import requests
import configparser
import zlib
import uuid
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import http.server
import socketserver
import threading

logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

config = configparser.ConfigParser()
config_file = 'config.ini'
config.read(config_file)

if not os.path.exists(config_file):
    config = configparser.ConfigParser()
    config['database'] = {
        'port': '12345'
    }
    config['file_settings'] = {
        'max_file_size_mb': '0',  # 0表示无限制，其他数字表示MB
        'enable_file_limit': 'false'
    }
    with open(config_file, 'w') as f:
        config.write(f)
        logging.info("Create config file")

REPO = "xhdndmm/cat-message"
CURRENT_VERSION = "v1.6"

# 创建图片存储目录
IMAGE_STORAGE_DIR = "image_storage"
if not os.path.exists(IMAGE_STORAGE_DIR):
    os.makedirs(IMAGE_STORAGE_DIR)

# 创建文件存储目录
FILE_STORAGE_DIR = "file_storage"
if not os.path.exists(FILE_STORAGE_DIR):
    os.makedirs(FILE_STORAGE_DIR)

if os.path.exists("chat.json"):
    try:
        with open("chat.json", "r") as file:
            MESSAGE_LOG = json.load(file)
    except Exception:
        MESSAGE_LOG = []
else:
    MESSAGE_LOG = []

clients = []
client_keys = {}  # 存储客户端密钥

def save_image(image_data):
    """保存图片并返回UUID"""
    image_id = str(uuid.uuid4())
    file_path = os.path.join(IMAGE_STORAGE_DIR, image_id)
    with open(file_path, 'wb') as f:
        f.write(image_data)
    return image_id

def get_image(image_id):
    """获取图片数据"""
    file_path = os.path.join(IMAGE_STORAGE_DIR, image_id)
    if not os.path.exists(file_path):
        return None
    with open(file_path, 'rb') as f:
        return f.read()

def save_file(file_data, file_name):
    """保存文件并返回UUID"""
    file_id = str(uuid.uuid4())
    file_path = os.path.join(FILE_STORAGE_DIR, file_id)
    with open(file_path, 'wb') as f:
        f.write(file_data)
    
    # 保存文件元数据
    metadata_path = os.path.join(FILE_STORAGE_DIR, f"{file_id}.meta")
    with open(metadata_path, 'w', encoding='utf-8') as f:
        json.dump({"original_name": file_name}, f)
    
    return file_id

def get_file(file_id):
    """获取文件数据"""
    file_path = os.path.join(FILE_STORAGE_DIR, file_id)
    if not os.path.exists(file_path):
        return None, None
    
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    # 获取原始文件名
    metadata_path = os.path.join(FILE_STORAGE_DIR, f"{file_id}.meta")
    original_name = "unknown_file"
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
                original_name = metadata.get("original_name", "unknown_file")
        except:
            pass
    
    return file_data, original_name

# 读取消息
def read_message(sock):
    try:
        raw_length = sock.recv(4)
        if not raw_length:
            return None
        msg_length = int.from_bytes(raw_length, byteorder='big')
        buffer = bytearray()
        while len(buffer) < msg_length:
            chunk = sock.recv(min(4096, msg_length - len(buffer)))
            if not chunk:
                return None
            buffer.extend(chunk)
        return buffer
    except Exception as e:
        logging.error(f"读取消息失败: {e}", exc_info=True)
        return None

def send_with_length(sock, data_bytes):
    try:
        length = len(data_bytes)
        sock.sendall(length.to_bytes(4, byteorder='big'))
        sock.sendall(data_bytes)
    except Exception as e:
        logging.error(f"发送数据失败: {e}")
        raise

def handle_client(client_socket):
    """客户端处理线程"""
    addr = client_socket.getpeername()
    logging.info(f"Verifying client from {addr}")
    global clients
    verified = False
    is_encrypted = False
    key_size = 0
    
    try:
        while True:
            data = read_message(client_socket)
            if not data:
                break
                
            if not verified:
                try:
                    data = json.loads(data.decode('utf-8'))
                    if data.get("command") == "verify":
                        payload = data.get("payload", "")
                        
                        if payload == "cat-message-v1.6-noenc":
                            # 无加密模式
                            is_encrypted = False
                            response_data = {
                                "type": "verify",
                                "status": "ok"
                            }
                            send_with_length(client_socket, json.dumps(response_data).encode('utf-8'))
                            verified = True
                            clients.append(client_socket)
                            client_keys[client_socket] = {"encrypted": False}
                            broadcast_online_users()
                            continue
                            
                        elif payload.startswith("cat-message-v1.6-enc-"):
                            # 加密模式
                            key_size = int(payload.split("-")[-1])
                            is_encrypted = True
                            
                            # 生成RSA密钥对
                            key = RSA.generate(key_size)
                            public_key = key.publickey()
                            private_key = key
                            
                            # 存储密钥
                            client_keys[client_socket] = {
                                'public_key': public_key,
                                'private_key': private_key,
                                'encrypted': True
                            }
                            
                            # 发送公钥给客户端
                            response_data = {
                                "type": "verify",
                                "status": "ok",
                                "public_key": base64.b64encode(public_key.export_key()).decode('utf-8')
                            }
                            send_with_length(client_socket, json.dumps(response_data).encode('utf-8'))
                            
                            # 等待接收客户端公钥
                            key_data = read_message(client_socket)
                            if key_data:
                                key_data = json.loads(key_data.decode('utf-8'))
                                if key_data.get("type") == "public_key":
                                    client_keys[client_socket]['peer_public_key'] = RSA.import_key(
                                        base64.b64decode(key_data["public_key"])
                                    )
                                    verified = True
                                    clients.append(client_socket)
                                    broadcast_online_users()
                                    continue
                        else:
                            response = {"type": "verify", "status": "fail", "message": "验证失败: 无效的验证信息"}
                            send_with_length(client_socket, json.dumps(response).encode('utf-8'))
                            break
                    else:
                        response = {"type": "verify", "status": "fail", "message": "验证失败: 未收到验证信息"}
                        send_with_length(client_socket, json.dumps(response).encode('utf-8'))
                        break
                except Exception as e:
                    logging.error(f"验证过程出错: {e}")
                    break
                    
            # 处理已验证的消息
            try:
                if is_encrypted and client_socket in client_keys and client_keys[client_socket].get('encrypted'):
                    # 解密消息
                    cipher = PKCS1_OAEP.new(client_keys[client_socket]['private_key'])
                    decrypted_data = cipher.decrypt(data)
                    data = json.loads(decrypted_data.decode('utf-8'))
                else:
                    # 无加密模式，直接解析
                    data = json.loads(data.decode('utf-8'))
                
                # 处理历史记录请求
                if data.get("command") == "load_history":
                    send_chat_history_to_client(client_socket)
                    continue
                
                # 处理图片消息
                if data.get("content_type") == "image":
                    image_data = base64.b64decode(data["message"])
                    image_id = save_image(image_data)
                    data["message"] = image_id
                
                # 处理文件消息
                elif data.get("content_type") == "file":
                    # 检查文件大小限制
                    enable_limit = config.getboolean('file_settings', 'enable_file_limit', fallback=False)
                    if enable_limit:
                        max_size_mb = config.getint('file_settings', 'max_file_size_mb', fallback=10)
                        file_size = data.get("file_size", 0)
                        if max_size_mb > 0 and file_size > max_size_mb * 1024 * 1024:
                            # 发送错误消息给客户端
                            error_msg = {
                                "type": "error",
                                "message": f"文件大小超过限制({max_size_mb}MB)"
                            }
                            if client_keys[client_socket].get('encrypted'):
                                cipher = PKCS1_OAEP.new(client_keys[client_socket]['peer_public_key'])
                                encrypted_data = cipher.encrypt(json.dumps(error_msg).encode('utf-8'))
                                send_with_length(client_socket, encrypted_data)
                            else:
                                send_with_length(client_socket, json.dumps(error_msg).encode('utf-8'))
                            continue
                    
                    file_data = base64.b64decode(data["message"])
                    file_name = data.get("file_name", "unknown_file")
                    file_id = save_file(file_data, file_name)
                    data["message"] = file_id
                
                # 广播消息给其他客户端
                for client in clients[:]:
                    if client != client_socket and client in client_keys:
                        try:
                            if client_keys[client].get('encrypted'):
                                cipher = PKCS1_OAEP.new(client_keys[client]['peer_public_key'])
                                encrypted_data = cipher.encrypt(json.dumps(data).encode('utf-8'))
                                send_with_length(client, encrypted_data)
                            else:
                                send_with_length(client, json.dumps(data).encode('utf-8'))
                        except Exception as e:
                            logging.error(f"广播消息失败: {e}")
                            if client in clients:
                                clients.remove(client)
                            try:
                                client.close()
                            except Exception:
                                pass
                
                # 存储消息
                MESSAGE_LOG.append(data)
                with open("chat.json", "w") as f:
                    json.dump(MESSAGE_LOG, f, ensure_ascii=False, indent=4)
                    
            except Exception as e:
                logging.error(f"处理消息失败: {e}")
                
    except Exception as e:
        logging.error(f"handle_client异常: {e}", exc_info=True)
    finally:
        if client_socket in clients:
            clients.remove(client_socket)
        if client_socket in client_keys:
            del client_keys[client_socket]
        try:
            client_socket.close()
        except Exception:
            pass
        broadcast_online_users()

def broadcast_online_users():
    global clients
    count = len(clients)
    message = json.dumps({"type": "online_users", "count": count})
    for client in clients[:]:
        try:
            if client in client_keys:
                if client_keys[client].get('encrypted'):
                    cipher = PKCS1_OAEP.new(client_keys[client]['peer_public_key'])
                    encrypted_data = cipher.encrypt(message.encode('utf-8'))
                    send_with_length(client, encrypted_data)
                else:
                    send_with_length(client, message.encode('utf-8'))
        except Exception as e:
            logging.error(f"发送在线人数失败: {e}")
            if client in clients:
                clients.remove(client)
            try:
                client.close()
            except Exception:
                pass

def save_message_to_file(username, message, ip, time):
    global MESSAGE_LOG
    MESSAGE_LOG.append({"username": username, "message": message, "ip": ip, "time": time})
    with open("chat.json", "w") as file:
        json.dump(MESSAGE_LOG, file, ensure_ascii=False, indent=4)

def broadcast(data, client_socket):
    """广播消息并存储"""
    global MESSAGE_LOG, clients
    MESSAGE_LOG.append(data)
    for client in clients[:]:
        if client != client_socket:
            try:
                send_with_length(client, data)
            except Exception as e:
                logging.error(f"广播失败: {e}")
                if client in clients:
                    clients.remove(client)
                try:
                    client.close()
                except Exception:
                    pass
    with open("chat.json", "w") as f:
        json.dump(MESSAGE_LOG, f, ensure_ascii=False, indent=4)

def send_to_client(message, client_socket):
    try:
        compressed = zlib.compress(message.encode('utf-8'))
        encrypted = base64.b64encode(compressed)
        send_with_length(client_socket, encrypted)
    except Exception as e:
        logging.error(f"Error sending message to client: {e}")
        if client_socket in clients:
            clients.remove(client_socket)
        try:
            client_socket.close()
        except Exception:
            pass

def send_chat_history_to_client(client_socket):
    """发送聊天历史给客户端"""
    try:
        for msg in MESSAGE_LOG[-20:]:  # 发送最近20条消息
            history_payload = {
                "type": "history",
                "data": [msg]
            }
            
            if client_socket in client_keys and client_keys[client_socket].get('encrypted'):
                cipher = PKCS1_OAEP.new(client_keys[client_socket]['peer_public_key'])
                encrypted_data = cipher.encrypt(json.dumps(history_payload).encode('utf-8'))
                send_with_length(client_socket, encrypted_data)
            else:
                send_with_length(client_socket, json.dumps(history_payload).encode('utf-8'))
    except Exception as e:
        logging.error(f"发送历史失败: {e}")
        if client_socket in clients:
            clients.remove(client_socket)
        try:
            client_socket.close()
        except Exception:
            pass

def get_latest_github_release(REPO):
    try:
        url = f"https://api.github.com/repos/{REPO}/releases/latest"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data.get("tag_name", None)
    except requests.RequestException as e:
        logging.warning(f"Failed to check for updates: {str(e)}")
        return None

def check_for_update():
    latest_version = get_latest_github_release(REPO)
    if latest_version is None:
        print("无法检查更新")
        return
    if latest_version == CURRENT_VERSION:
        print("当前已是最新版本")
    else:
        print(f"发现新版本: {latest_version}\n注意：不要随便升级，本项目需要确认服务端版本和客户端版本是否一致！")

class ImageRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/image/'):
            image_id = self.path[7:]  # 移除 '/image/' 前缀
            image_data = get_image(image_id)
            if image_data:
                self.send_response(200)
                self.send_header('Content-type', 'image/png')
                self.end_headers()
                self.wfile.write(image_data)
            else:
                self.send_response(404)
                self.end_headers()
        elif self.path.startswith('/file/'):
            file_id = self.path[6:]  # 移除 '/file/' 前缀
            file_data, original_name = get_file(file_id)
            if file_data:
                self.send_response(200)
                self.send_header('Content-type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{original_name}"')
                self.end_headers()
                self.wfile.write(file_data)
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

def start_image_server():
    """启动图片服务器"""
    handler = ImageRequestHandler
    httpd = socketserver.TCPServer(("", 12346), handler)  # 使用不同端口避免冲突
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

def start_server():
    # 启动图片服务器
    start_image_server()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    port = config.getint('database', 'port')
    server.bind(('0.0.0.0', port))
    server.listen(5)
    server.settimeout(5)
    logging.info(f"Server started on port {port}")

    shutdown_flag = False

    def input_listener():
        nonlocal shutdown_flag
        while True:
            cmd = input().strip().lower()
            if cmd == "clear_history":
                global MESSAGE_LOG
                MESSAGE_LOG = []
                try:
                    with open("chat.json", "w") as file:
                        file.write("[]")
                    logging.info("Chat history cleared")
                    print("聊天记录已清除")
                except Exception as e:
                    logging.error(f"Clear chat history error: {e}")
            elif cmd == "stop":
                shutdown_flag = True
                break
            elif cmd == "check_update":
                check_for_update()
            elif cmd == "help":
                print('''
                    ####################################################################
                    cat-message-server-v1.6
                    https://github.com/xhdndmm/cat-message      
                    你可以输入stop来停止服务器
                    You can enter stop to stop the server
                    你可以输入clear_history来清除聊天记录
                    You can enter clear_history to clear chat history   
                    你可以输入check_update来检查更新
                    You can enter check_update to check for updates   
                    服务器日志：./server.log      
                    Server log: ./server.log
                    聊天记录：./chat.json
                    Chat log: ./chat.json
                    配置文件：./config.ini
                    Config file：./config.ini
                    图片存储：./image_storage/
                    Image storage: ./image_storage/
                    文件存储：./file_storage/
                    File storage: ./file_storage/
                    请确保你的服务器已经开启12345端口（聊天服务）和12346端口（图片和文件服务）
                    Please make sure your server has opened port 12345 (chat service) and port 12346 (image and file service)
                    ####################################################################
                    ''')
            else:
                print("无效命令")

    threading.Thread(target=input_listener, daemon=True).start()

    try:
        while not shutdown_flag:
            try:
                client_socket, addr = server.accept()
                logging.info(f"Connection from {addr} established")
                # 检查socket是否有效
                try:
                    client_socket.settimeout(2)
                    test = client_socket.recv(1, socket.MSG_PEEK)
                    client_socket.settimeout(None)
                except Exception:
                    client_socket.close()
                    continue
                threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()
            except socket.timeout:
                continue
            except socket.error as e:
                logging.error(f"Socket error: {e}")
    except Exception as e:
        logging.error(f"Error in server loop: {e}")
    finally:
        for client in clients:
            try:
                client.close()
            except Exception:
                pass
        server.close()
        logging.info("Server shut down gracefully")

if __name__ == "__main__":
  start_server()