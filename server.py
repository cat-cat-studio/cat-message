#https://github.com/xhdndmm/cat-message

import socket
import threading
import json
import os
import base64
from datetime import datetime
import logging

print("cat-message-server-v1.1")

logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

if os.path.exists("chat.json"):
    try:
        with open("chat.json", "r") as file:
            MESSAGE_LOG = json.load(file)
    except Exception:
        MESSAGE_LOG = []
else:
    MESSAGE_LOG = []

clients = []

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

def handle_client(client_socket):
    while True:
        try:
            raw_message = read_message(client_socket)
            if not raw_message:
                break
            decoded = base64.b64decode(raw_message).decode('utf-8')
            data = json.loads(decoded)
            data["ip"] = client_socket.getpeername()[0]
            if "time" not in data:
                data["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            processed_message = json.dumps(data)
            broadcast(processed_message, client_socket, data)
        except Exception as e:
            logging.error(f"Client disconnected: {e}")
            break
    if client_socket in clients:
        clients.remove(client_socket)
    client_socket.close()

def save_message_to_file(username, message, ip, time):
    global MESSAGE_LOG
    MESSAGE_LOG.append({"username": username, "message": message, "ip": ip, "time": time})
    with open("chat.json", "w") as file:
        json.dump(MESSAGE_LOG, file, ensure_ascii=False, indent=4)

def broadcast(message, client_socket, data):
    for client in clients:
        if client != client_socket:
            send_to_client(message, client)
    save_message_to_file(data["username"], data["message"], data["ip"], data["time"])

def send_to_client(message, client_socket):
    try:
        encrypted = base64.b64encode(message.encode('utf-8'))
        client_socket.sendall(encrypted)
    except Exception as e:
        logging.error(f"Error sending message to client: {e}")
        if client_socket in clients:
            clients.remove(client_socket)
        client_socket.close()

def send_chat_history(client_socket):
    try:
        history_payload = {"type": "history", "data": MESSAGE_LOG}
        json_payload = json.dumps(history_payload)
        encrypted = base64.b64encode(json_payload.encode('utf-8'))
        client_socket.sendall(encrypted)
    except Exception as e:
        logging.error(f"Error sending history: {e}")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 12345))
    server.listen(5)
    logging.info("Server started on port 12345")

    while True:
        try:
            client_socket, addr = server.accept()
            logging.info(f"Connection from {addr} established")
            clients.append(client_socket)
            send_chat_history(client_socket)
            threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()
        except Exception as e:
            logging.error(f"Error accepting connection: {e}")

start_server()