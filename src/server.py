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

logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

config = configparser.ConfigParser()
config_file = 'config.ini'
config.read(config_file)

if not os.path.exists(config_file):
    config = configparser.ConfigParser()
    config['database'] = {
        'port': '12345'
    }
    with open(config_file, 'w') as f:
        config.write(f)
        logging.info("Create config file")

REPO = "xhdndmm/cat-message"
CURRENT_VERSION = "v1.6"

if os.path.exists("chat.json"):
    try:
        with open("chat.json", "r") as file:
            MESSAGE_LOG = json.load(file)
    except Exception:
        MESSAGE_LOG = []
else:
    MESSAGE_LOG = []

clients = []

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
                break
            buffer.extend(chunk)
        try:
            # 先解base64再解压
            decompressed = zlib.decompress(base64.b64decode(buffer))
            return json.loads(decompressed.decode('utf-8'))
        except:
            # 兼容旧数据
            return json.loads(base64.b64decode(buffer).decode('utf-8'))
    except Exception as e:
        logging.error(f"读取消息失败: {e}")
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
    global clients
    verified = False
    try:
        while True:
            data = read_message(client_socket)
            if not data:
                break
            if not verified:
                if data.get("command") == "verify":
                    if data.get("payload") == "cat-message-v1.6":
                        response = {"type": "verify", "status": "ok"}
                        send_to_client(json.dumps(response), client_socket)
                        verified = True
                        broadcast_online_users()
                        continue
                    else:
                        response = {"type": "verify", "status": "fail", "message": "验证失败: 无效的验证信息"}
                        send_to_client(json.dumps(response), client_socket)
                        break
                else:
                    response = {"type": "verify", "status": "fail", "message": "验证失败: 未收到验证信息"}
                    send_to_client(json.dumps(response), client_socket)
                    break
            # 处理历史请求（分页加载）
            if data.get("command") == "load_history":
                page = data.get("page", 0)
                page_size = 20  # 每页20条
                start = max(0, len(MESSAGE_LOG) - (page+1)*page_size)
                end = len(MESSAGE_LOG) - page*page_size
                send_chat_history(client_socket, start, end)
                continue
            # 存储消息时记录类型
            msg_data = {
                "username": data["username"],
                "message": data["message"],
                "ip": client_socket.getpeername()[0],
                "time": data.get("time", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                "content_type": data.get("content_type", "text")
            }
            broadcast(msg_data, client_socket)
    except Exception as e:
        logging.error(f"handle_client异常: {e}")
    finally:
        if client_socket in clients:
            clients.remove(client_socket)
        try:
            client_socket.close()
        except Exception:
            pass
        broadcast_online_users()

def broadcast_online_users():
    global clients
    count = len(clients)
    message = json.dumps({"type": "online_users", "count": count})
    # 复制clients列表，避免遍历时修改
    for client in clients[:]:
        try:
            send_to_client(message, client)
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
    message = json.dumps(data)
    for client in clients[:]:
        if client != client_socket:
            try:
                compressed = zlib.compress(message.encode('utf-8'))
                encrypted = base64.b64encode(compressed)
                send_with_length(client, encrypted)
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

def send_chat_history(client_socket, start, end):
    """分页发送历史记录"""
    for msg in MESSAGE_LOG[start:end]:
        try:
            history_payload = {
                "type": "history",
                "data": [msg]
            }
            json_data = json.dumps(history_payload).encode('utf-8')
            compressed = zlib.compress(json_data)
            encrypted = base64.b64encode(compressed)
            send_with_length(client_socket, encrypted)
        except Exception as e:
            logging.error(f"发送历史失败: {e}")
            if client_socket in clients:
                clients.remove(client_socket)
            try:
                client_socket.close()
            except Exception:
                pass
            break

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

def start_server():
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
                    请确保你的服务器已经开启12345端口（或者其他端口）
                    Please make sure your server has opened port 12345 (or other ports)
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
                clients.append(client_socket)
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