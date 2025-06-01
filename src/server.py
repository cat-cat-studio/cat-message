#python3
#server.py
#https://github.com/xhdndmm/cat-message

print("cat-message-server-v1.8")
print("正在导入模块...")

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
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import http.server
import socketserver
import threading
import time

print("模块导入完成")

# RSA密钥缓存系统
class RSAKeyCache:
    def __init__(self):
        self.cache = {2048: [], 4096: [], 8192: []}
        self.max_cache_size = 3  # 每种密钥类型最多缓存3个
        self.generating = set()  # 正在生成的密钥大小
        
    def get_key_pair(self, key_size):
        """获取密钥对，如果缓存中没有则生成新的"""
        if self.cache[key_size]:
            return self.cache[key_size].pop()
        else:
            # 缓存中没有，直接生成
            return self._generate_key_pair(key_size)
            
    def _generate_key_pair(self, key_size):
        """生成新的密钥对"""
        start_time = time.time()
        key = RSA.generate(key_size)
        end_time = time.time()
        logging.info(f"RSA{key_size} 密钥生成耗时 {end_time - start_time:.2f} 秒")
        return {
            'key': key,
            'public_key': key.publickey(),
            'private_key': key
        }
        
    def pregenerate_keys(self):
        """在后台预生成一些密钥"""
        def generate_worker():
            for key_size in [2048, 4096]:  # 预生成常用的密钥大小
                while len(self.cache[key_size]) < self.max_cache_size:
                    if key_size not in self.generating:
                        self.generating.add(key_size)
                        try:
                            key_pair = self._generate_key_pair(key_size)
                            self.cache[key_size].append(key_pair)
                            logging.info(f"预生成RSA{key_size}密钥完成，缓存数量: {len(self.cache[key_size])}")
                        except Exception as e:
                            logging.error(f"预生成RSA{key_size}密钥失败: {e}")
                        finally:
                            self.generating.discard(key_size)
                    time.sleep(1)  # 避免CPU占用过高
                        
        # 启动后台生成线程
        thread = threading.Thread(target=generate_worker, daemon=True)
        thread.start()

# 创建全局密钥缓存
rsa_cache = RSAKeyCache()

logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

config = configparser.ConfigParser()
config_file = 'config.ini'
config.read(config_file)

if not os.path.exists(config_file):
    config = configparser.ConfigParser()
    config['server'] = {
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
CURRENT_VERSION = "v1.8"

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

# 房间管理数据结构
rooms = {}  # 房间字典: {房间名: {"users": [客户端socket列表], "created_time": 创建时间}}
client_rooms = {}  # 客户端房间映射: {客户端socket: 房间名}
client_usernames = {}  # 客户端用户名映射: {客户端socket: 用户名}

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
                        
                        if payload == "cat-message-v1.8-noenc":
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
                            
                        elif payload.startswith("cat-message-v1.8-enc-"):
                            # 加密模式
                            key_size = int(payload.split("-")[-1])
                            is_encrypted = True
                            
                            try:
                                # 生成RSA密钥对（这可能耗时较长，特别是4096和8192位）
                                logging.info(f"正在为客户端 {addr} 获取 {key_size} 位RSA密钥...")
                                
                                # 从缓存获取或生成新的密钥对
                                key_pair = rsa_cache.get_key_pair(key_size)
                                
                                # 存储密钥
                                client_keys[client_socket] = {
                                    'public_key': key_pair['public_key'],
                                    'private_key': key_pair['private_key'],
                                    'encrypted': True
                                }
                                
                                # 发送公钥给客户端
                                response_data = {
                                    "type": "verify",
                                    "status": "ok",
                                    "public_key": base64.b64encode(key_pair['public_key'].export_key()).decode('utf-8')
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
                                        logging.info(f"客户端 {addr} RSA{key_size} 加密验证成功")
                                        continue
                                        
                            except Exception as e:
                                logging.error(f"RSA密钥处理失败: {e}")
                                response = {
                                    "type": "verify", 
                                    "status": "fail", 
                                    "message": f"服务器密钥处理失败: {str(e)}"
                                }
                                send_with_length(client_socket, json.dumps(response).encode('utf-8'))
                                break
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
                    # 使用混合解密消息
                    decrypted_data = hybrid_decrypt(data, client_keys[client_socket]['private_key'])
                    data = json.loads(decrypted_data.decode('utf-8'))
                else:
                    # 无加密模式，直接解析
                    data = json.loads(data.decode('utf-8'))
                
                # 处理历史记录请求
                if data.get("command") == "load_history":
                    send_chat_history_to_client(client_socket)
                    continue
                
                # 处理心跳消息
                elif data.get("command") == "heartbeat":
                    # 发送心跳响应
                    heartbeat_response = {
                        "command": "heartbeat",
                        "status": "ok",
                        "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    try:
                        response_data = json.dumps(heartbeat_response).encode('utf-8')
                        if client_keys[client_socket].get('encrypted'):
                            encrypted_data = hybrid_encrypt(response_data, client_keys[client_socket]['peer_public_key'])
                            send_with_length(client_socket, encrypted_data)
                        else:
                            send_with_length(client_socket, response_data)
                    except Exception as e:
                        logging.error(f"发送心跳响应失败: {e}")
                    continue
                
                # 处理房间管理命令
                elif data.get("command") == "create_room":
                    handle_create_room(client_socket, data)
                    continue
                elif data.get("command") == "join_room":
                    handle_join_room(client_socket, data)
                    continue
                elif data.get("command") == "leave_room":
                    handle_leave_room(client_socket, data)
                    continue
                elif data.get("command") == "get_rooms":
                    handle_get_rooms(client_socket)
                    continue
                elif data.get("command") == "get_users":
                    handle_get_users(client_socket, data)
                    continue
                elif data.get("command") == "private_message":
                    handle_private_message(client_socket, data)
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
                                encrypted_data = hybrid_encrypt(json.dumps(error_msg).encode('utf-8'), client_keys[client_socket]['peer_public_key'])
                                send_with_length(client_socket, encrypted_data)
                            else:
                                send_with_length(client_socket, json.dumps(error_msg).encode('utf-8'))
                            continue
                    
                    file_data = base64.b64decode(data["message"])
                    file_name = data.get("file_name", "unknown_file")
                    file_id = save_file(file_data, file_name)
                    data["message"] = file_id
                
                # 广播消息给其他客户端
                sender_room = client_rooms.get(client_socket)
                for client in clients[:]:
                    if client != client_socket and client in client_keys:
                        # 只向同一房间的用户广播消息
                        if sender_room and client_rooms.get(client) == sender_room:
                            try:
                                if client_keys[client].get('encrypted'):
                                    encrypted_data = hybrid_encrypt(json.dumps(data).encode('utf-8'), client_keys[client]['peer_public_key'])
                                    send_with_length(client, encrypted_data)
                                else:
                                    send_with_length(client, json.dumps(data).encode('utf-8'))
                            except Exception as e:
                                logging.error(f"广播消息失败: {e}")
                                remove_client_from_all_rooms(client)
                                if client in clients:
                                    clients.remove(client)
                                try:
                                    client.close()
                                except Exception:
                                    pass
                        elif not sender_room:
                            # 如果发送者不在任何房间，则向所有不在房间的用户广播
                            if not client_rooms.get(client):
                                try:
                                    if client_keys[client].get('encrypted'):
                                        encrypted_data = hybrid_encrypt(json.dumps(data).encode('utf-8'), client_keys[client]['peer_public_key'])
                                        send_with_length(client, encrypted_data)
                                    else:
                                        send_with_length(client, json.dumps(data).encode('utf-8'))
                                except Exception as e:
                                    logging.error(f"广播消息失败: {e}")
                                    remove_client_from_all_rooms(client)
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
        # 清理客户端相关数据
        remove_client_from_all_rooms(client_socket)
        if client_socket in clients:
            clients.remove(client_socket)
        if client_socket in client_keys:
            del client_keys[client_socket]
        if client_socket in client_usernames:
            del client_usernames[client_socket]
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
                    encrypted_data = hybrid_encrypt(message.encode('utf-8'), client_keys[client]['peer_public_key'])
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
                encrypted_data = hybrid_encrypt(json.dumps(history_payload).encode('utf-8'), client_keys[client_socket]['peer_public_key'])
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
    try:
        handler = ImageRequestHandler
        httpd = socketserver.TCPServer(("", 12346), handler)  # 使用不同端口避免冲突
        
        # 添加成功启动日志
        logging.info("图片/文件服务器正在启动，端口: 12346")
        print("图片/文件服务器正在启动，端口: 12346")
        
        # 启动服务器线程
        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()
        
        # 验证服务器是否成功启动
        logging.info("图片/文件服务器已启动成功")
        print("✅ 图片/文件服务器已启动成功")
        
    except OSError as e:
        if e.errno == 48 or "Address already in use" in str(e):
            error_msg = "端口12346已被占用，请检查是否有其他程序使用此端口"
            logging.error(error_msg)
            print(f"❌ 错误: {error_msg}")
        elif e.errno == 13 or "Permission denied" in str(e):
            error_msg = "权限不足，无法绑定端口12346"
            logging.error(error_msg)
            print(f"❌ 错误: {error_msg}")
        else:
            error_msg = f"无法启动图片/文件服务器: {str(e)}"
            logging.error(error_msg)
            print(f"❌ 错误: {error_msg}")
        
        print("⚠️  图片和文件传输功能将不可用")
        print("⚠️  请检查端口12346是否被占用或权限设置")
        
    except Exception as e:
        error_msg = f"图片/文件服务器启动异常: {str(e)}"
        logging.error(error_msg)
        print(f"❌ 意外错误: {error_msg}")
        print("⚠️  图片和文件传输功能将不可用")

def start_server():
    # 启动图片服务器
    start_image_server()
    
    # 启动RSA密钥预生成
    logging.info("启动RSA密钥预生成...")
    rsa_cache.pregenerate_keys()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    port = config.getint('server', 'port')
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
                    cat-message-server-v1.8
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

def hybrid_encrypt(data, public_key):
    """服务器端混合加密函数"""
    try:
        if not data:
            raise Exception("加密数据为空")
        
        # 如果数据很小，直接使用RSA加密
        if len(data) <= 400:
            cipher = PKCS1_OAEP.new(public_key)
            return cipher.encrypt(data)
        
        # 数据较大，使用混合加密
        # 1. 生成随机AES密钥（256位）
        aes_key = get_random_bytes(32)
        
        # 2. 使用AES加密数据
        cipher_aes = AES.new(aes_key, AES.MODE_CBC)
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher_aes.encrypt(padded_data)
        
        # 3. 使用RSA加密AES密钥
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        # 4. 构造最终数据：标志 + RSA加密的AES密钥 + IV + AES加密的数据
        result = b"HYBRID" + len(encrypted_aes_key).to_bytes(2, 'big') + encrypted_aes_key + cipher_aes.iv + encrypted_data
        
        return result
        
    except Exception as e:
        raise Exception(f"服务器端混合加密失败: {str(e)}")

def hybrid_decrypt(encrypted_data, private_key):
    """服务器端混合解密函数"""
    try:
        if not encrypted_data:
            raise Exception("解密数据为空")
        
        # 检查是否为混合加密数据
        if not encrypted_data.startswith(b"HYBRID"):
            # 不是混合加密，使用传统RSA解密
            cipher = PKCS1_OAEP.new(private_key)
            return cipher.decrypt(encrypted_data)
        
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
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        
        # 2. 使用AES密钥解密数据
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = cipher_aes.decrypt(aes_encrypted_data)
        
        # 3. 去除填充
        data = unpad(padded_data, AES.block_size)
        
        return data
        
    except Exception as e:
        raise Exception(f"服务器端混合解密失败: {str(e)}")

def remove_client_from_all_rooms(client_socket):
    """从所有房间中移除客户端"""
    if client_socket in client_rooms:
        room_name = client_rooms[client_socket]
        if room_name in rooms and client_socket in rooms[room_name]["users"]:
            rooms[room_name]["users"].remove(client_socket)
            # 如果房间为空，删除房间
            if not rooms[room_name]["users"]:
                del rooms[room_name]
                logging.info(f"房间 '{room_name}' 已删除（无用户）")
            else:
                # 通知房间内其他用户
                broadcast_users_update(room_name)
        del client_rooms[client_socket]

def handle_create_room(client_socket, data):
    """处理创建房间请求"""
    room_name = data.get("room_name", "").strip()
    username = data.get("username", "").strip()
    
    if not room_name:
        send_room_response(client_socket, "create", False, "房间名称不能为空", "")
        return
    
    if room_name in rooms:
        send_room_response(client_socket, "create", False, "房间已存在", room_name)
        return
    
    # 创建新房间
    rooms[room_name] = {
        "users": [client_socket],
        "created_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    client_rooms[client_socket] = room_name
    client_usernames[client_socket] = username
    
    send_room_response(client_socket, "create", True, "房间创建成功", room_name)
    broadcast_rooms_update()
    logging.info(f"用户 {username} 创建了房间 '{room_name}'")

def handle_join_room(client_socket, data):
    """处理加入房间请求"""
    room_name = data.get("room_name", "").strip()
    username = data.get("username", "").strip()
    
    if not room_name:
        send_room_response(client_socket, "join", False, "房间名称不能为空", "")
        return
    
    if room_name not in rooms:
        send_room_response(client_socket, "join", False, "房间不存在", room_name)
        return
    
    # 如果用户已在其他房间，先离开
    if client_socket in client_rooms:
        old_room = client_rooms[client_socket]
        if old_room != room_name:
            handle_leave_room_internal(client_socket)
    
    # 加入新房间
    if client_socket not in rooms[room_name]["users"]:
        rooms[room_name]["users"].append(client_socket)
    client_rooms[client_socket] = room_name
    client_usernames[client_socket] = username
    
    send_room_response(client_socket, "join", True, "成功加入房间", room_name)
    broadcast_users_update(room_name)
    broadcast_rooms_update()
    logging.info(f"用户 {username} 加入了房间 '{room_name}'")

def handle_leave_room(client_socket, data):
    """处理离开房间请求"""
    room_name = data.get("room_name", "").strip()
    username = data.get("username", "").strip()
    
    if client_socket not in client_rooms:
        send_room_response(client_socket, "leave", False, "您不在任何房间中", room_name)
        return
    
    current_room = client_rooms[client_socket]
    if room_name and current_room != room_name:
        send_room_response(client_socket, "leave", False, "您不在指定房间中", room_name)
        return
    
    handle_leave_room_internal(client_socket)
    send_room_response(client_socket, "leave", True, "成功离开房间", current_room)
    logging.info(f"用户 {username} 离开了房间 '{current_room}'")

def handle_leave_room_internal(client_socket):
    """内部离开房间处理"""
    if client_socket in client_rooms:
        room_name = client_rooms[client_socket]
        if room_name in rooms and client_socket in rooms[room_name]["users"]:
            rooms[room_name]["users"].remove(client_socket)
            # 如果房间为空，删除房间
            if not rooms[room_name]["users"]:
                del rooms[room_name]
                logging.info(f"房间 '{room_name}' 已删除（无用户）")
            else:
                # 通知房间内其他用户
                broadcast_users_update(room_name)
        del client_rooms[client_socket]
        broadcast_rooms_update()

def handle_get_rooms(client_socket):
    """处理获取房间列表请求"""
    rooms_data = []
    for room_name, room_info in rooms.items():
        rooms_data.append({
            "name": room_name,
            "user_count": len(room_info["users"]),
            "created_time": room_info["created_time"]
        })
    
    response = {
        "command": "rooms_update",
        "rooms": rooms_data
    }
    
    try:
        response_data = json.dumps(response).encode('utf-8')
        if client_keys[client_socket].get('encrypted'):
            encrypted_data = hybrid_encrypt(response_data, client_keys[client_socket]['peer_public_key'])
            send_with_length(client_socket, encrypted_data)
        else:
            send_with_length(client_socket, response_data)
    except Exception as e:
        logging.error(f"发送房间列表失败: {e}")

def handle_get_users(client_socket, data):
    """处理获取用户列表请求"""
    room_name = data.get("room_name", "")
    
    if not room_name or room_name not in rooms:
        # 返回空用户列表
        response = {
            "command": "users_update",
            "room_name": room_name,
            "users": []
        }
    else:
        users_data = []
        for user_socket in rooms[room_name]["users"]:
            username = client_usernames.get(user_socket, "未知用户")
            users_data.append({
                "username": username,
                "status": "online"
            })
        
        response = {
            "command": "users_update",
            "room_name": room_name,
            "users": users_data
        }
    
    try:
        response_data = json.dumps(response).encode('utf-8')
        if client_keys[client_socket].get('encrypted'):
            encrypted_data = hybrid_encrypt(response_data, client_keys[client_socket]['peer_public_key'])
            send_with_length(client_socket, encrypted_data)
        else:
            send_with_length(client_socket, response_data)
    except Exception as e:
        logging.error(f"发送用户列表失败: {e}")

def handle_private_message(client_socket, data):
    """处理私聊消息"""
    target_username = data.get("target_username", "")
    message = data.get("message", "")
    from_username = data.get("username", "")
    timestamp = data.get("time", "")
    
    if not target_username or not message:
        return
    
    # 查找目标用户的socket
    target_socket = None
    for socket, username in client_usernames.items():
        if username == target_username:
            target_socket = socket
            break
    
    if not target_socket or target_socket not in clients:
        # 目标用户不在线，可以选择存储离线消息或直接忽略
        return
    
    # 发送私聊消息给目标用户
    private_msg = {
        "command": "private_message",
        "from_username": from_username,
        "message": message,
        "time": timestamp
    }
    
    try:
        response_data = json.dumps(private_msg).encode('utf-8')
        if client_keys[target_socket].get('encrypted'):
            encrypted_data = hybrid_encrypt(response_data, client_keys[target_socket]['peer_public_key'])
            send_with_length(target_socket, encrypted_data)
        else:
            send_with_length(target_socket, response_data)
        logging.info(f"私聊消息从 {from_username} 发送到 {target_username}")
    except Exception as e:
        logging.error(f"发送私聊消息失败: {e}")

def send_room_response(client_socket, action, success, message, room_name):
    """发送房间操作响应"""
    response = {
        "command": "room_response",
        "action": action,
        "success": success,
        "message": message,
        "room_name": room_name
    }
    
    try:
        response_data = json.dumps(response).encode('utf-8')
        if client_keys[client_socket].get('encrypted'):
            encrypted_data = hybrid_encrypt(response_data, client_keys[client_socket]['peer_public_key'])
            send_with_length(client_socket, encrypted_data)
        else:
            send_with_length(client_socket, response_data)
    except Exception as e:
        logging.error(f"发送房间响应失败: {e}")

def broadcast_users_update(room_name):
    """广播用户列表更新"""
    if room_name not in rooms:
        return
    
    users_data = []
    for user_socket in rooms[room_name]["users"]:
        username = client_usernames.get(user_socket, "未知用户")
        users_data.append({
            "username": username,
            "status": "online"
        })
    
    response = {
        "command": "users_update",
        "room_name": room_name,
        "users": users_data
    }
    
    # 向房间内所有用户广播
    for user_socket in rooms[room_name]["users"][:]:
        try:
            response_data = json.dumps(response).encode('utf-8')
            if client_keys[user_socket].get('encrypted'):
                encrypted_data = hybrid_encrypt(response_data, client_keys[user_socket]['peer_public_key'])
                send_with_length(user_socket, encrypted_data)
            else:
                send_with_length(user_socket, response_data)
        except Exception as e:
            logging.error(f"广播用户列表更新失败: {e}")

def broadcast_rooms_update():
    """广播房间列表更新"""
    rooms_data = []
    for room_name, room_info in rooms.items():
        rooms_data.append({
            "name": room_name,
            "user_count": len(room_info["users"]),
            "created_time": room_info["created_time"]
        })
    
    response = {
        "command": "rooms_update",
        "rooms": rooms_data
    }
    
    # 向所有客户端广播
    for client in clients[:]:
        try:
            response_data = json.dumps(response).encode('utf-8')
            if client_keys[client].get('encrypted'):
                encrypted_data = hybrid_encrypt(response_data, client_keys[client]['peer_public_key'])
                send_with_length(client, encrypted_data)
            else:
                send_with_length(client, response_data)
        except Exception as e:
            logging.error(f"广播房间列表更新失败: {e}")

if __name__ == "__main__":
  start_server()