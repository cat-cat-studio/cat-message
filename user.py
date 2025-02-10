#https://github.com/xhdndmm/cat-message

import tkinter as tk
from tkinter import scrolledtext
import socket
import threading
import json
import base64
from datetime import datetime

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

def send_message():
    message = entry.get()
    if message.strip():
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        payload = {"username": username, "message": message, "time": current_time}
        json_payload = json.dumps(payload)
        send_to_server(json_payload)
        chat_area.insert(tk.END, f"You ({current_time}): {message}\n")
        entry.delete(0, tk.END)

def send_to_server(message):
    try:
        encrypted = base64.b64encode(message.encode('utf-8'))
        client_socket.sendall(encrypted)
    except Exception as e:
        print(f"Error sending message: {e}")

def receive_message():
    while True:
        try:
            combined = read_message(client_socket)
            if not combined:
                break
            decoded = base64.b64decode(combined).decode('utf-8')
            data = json.loads(decoded)
            if data.get("type") == "history":
                for msg in data["data"]:
                    chat_area.insert(tk.END, f"{msg['username']} ({msg['time']}): {msg['message']}\n")
                continue
            formatted_message = f"{data['username']} ({data.get('time', 'unknown')}): {data['message']}"
            chat_area.insert(tk.END, formatted_message + "\n")
        except Exception as e:
            print(f"An error occurred: {e}")
            client_socket.close()
            break

def start_client(server_ip, user):
    global client_socket, username
    username = user
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((server_ip, 12345))
        threading.Thread(target=receive_message, daemon=True).start()
    except Exception as e:
        print(f"Error connecting to server: {e}")

def connect_client():
    server_ip = server_ip_entry.get().strip()
    user = username_entry.get().strip()
    if server_ip and user:
        start_client(server_ip, user)
        connect_button.config(state=tk.DISABLED)
        server_ip_entry.config(state=tk.DISABLED)
        username_entry.config(state=tk.DISABLED)

root = tk.Tk()
root.title("cat-message-user")

connection_frame = tk.Frame(root)
connection_frame.grid(row=0, column=0, columnspan=2, pady=5)

tk.Label(connection_frame, text="服务器IP:").grid(row=0, column=0, padx=5)
server_ip_entry = tk.Entry(connection_frame, width=20)
server_ip_entry.grid(row=0, column=1, padx=5)

tk.Label(connection_frame, text="用户名:").grid(row=0, column=2, padx=5)
username_entry = tk.Entry(connection_frame, width=20)
username_entry.grid(row=0, column=3, padx=5)

connect_button = tk.Button(connection_frame, text="连接", command=connect_client)
connect_button.grid(row=0, column=4, padx=5)

chat_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=50, height=20)
chat_area.grid(row=1, column=0, columnspan=2)

entry = tk.Entry(root, width=40)
entry.grid(row=2, column=0, padx=5, pady=5)
send_button = tk.Button(root, text="Send", command=send_message)
send_button.grid(row=2, column=1, padx=5, pady=5)

root.mainloop()