import socket
import threading
import json
import os
from cryptography.fernet import Fernet

# ================== CONFIG ==================
HOST = '0.0.0.0'  # Écoute sur toutes les interfaces
PORT = 2122
USERS_FILE = "users.json"
MESSAGES_DIR = "messages"
OFFLINE_DIR = "offline_messages"
# ===========================================

os.makedirs(MESSAGES_DIR, exist_ok=True)
os.makedirs(OFFLINE_DIR, exist_ok=True)

# Load or create users database
if os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'r') as f:
        users = json.load(f)
else:
    users = {}

clients = {}  # Active connections {user_id: conn}

def save_users():
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

def handle_client(conn, addr):
    print(f"[+] Connected by {addr}")
    user_id = None
    try:
        conn.send("User ID: ".encode('utf-8'))
        user_id = conn.recv(1024).decode('utf-8').strip()
        conn.send("Password: ".encode('utf-8'))
        password = conn.recv(1024).decode('utf-8').strip()

        if user_id not in users:
            users[user_id] = password
            save_users()
            conn.send("User created.\n".encode('utf-8'))
            print(f"[+] New user: {user_id}")
        elif users[user_id] != password:
            conn.send("Incorrect password.\n".encode('utf-8'))
            conn.close()
            print(f"[-] Incorrect password for {user_id} from {addr}")
            return
        else:
            conn.send("Successfully connected.\n".encode('utf-8'))
            print(f"[+] Successful login: {user_id}")

        clients[user_id] = conn

        # Envoyer les messages hors-ligne
        offline_file = os.path.join(OFFLINE_DIR, f"{user_id}.json")
        if os.path.exists(offline_file):
            with open(offline_file, 'r') as f:
                offline_msgs = json.load(f)
            for packet in offline_msgs:
                fernet = Fernet(packet['key'].encode('utf-8'))
                decrypted_msg = fernet.decrypt(packet['message'].encode('utf-8')).decode('utf-8')
                conn.send(f"[{packet['from']}] {decrypted_msg}\n".encode('utf-8'))
            os.remove(offline_file)

        while True:
            data = conn.recv(4096)
            if not data:
                break
            try:
                packet = json.loads(data.decode('utf-8'))
                key = packet['key'].encode('utf-8')
                encrypted_message = packet['message'].encode('utf-8')
                to_user = packet.get('to')
                fernet = Fernet(key)
                message = fernet.decrypt(encrypted_message).decode('utf-8')
                print(f"[{user_id}] -> [{to_user}]: {message}")

                # Historique
                history_file = os.path.join(MESSAGES_DIR, f"{user_id}_to_{to_user}.txt")
                with open(history_file, 'a') as fmsg:
                    fmsg.write(message + "\n")

                # Envoyer ou stocker hors-ligne
                if to_user in clients:
                    clients[to_user].send(f"[{user_id}] {message}".encode('utf-8'))
                    conn.send(f"Message sent to {to_user}\n".encode('utf-8'))
                else:
                    offline_file = os.path.join(OFFLINE_DIR, f"{to_user}.json")
                    if os.path.exists(offline_file):
                        with open(offline_file, 'r') as f:
                            offline_msgs = json.load(f)
                    else:
                        offline_msgs = []
                    offline_msgs.append({'from': user_id, 'key': key.decode('utf-8'), 'message': encrypted_message.decode('utf-8')})
                    with open(offline_file, 'w') as f:
                        json.dump(offline_msgs, f)
                    conn.send(f"{to_user} is offline. Message saved.\n".encode('utf-8'))

            except Exception as e:
                conn.send(f"Error: {e}\n".encode('utf-8'))

    finally:
        if user_id in clients:
            clients.pop(user_id)
        conn.close()
        print(f"[-] Disconnected {addr}")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
