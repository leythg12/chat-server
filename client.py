import socket
import json
import threading
from tkinter import Tk, Text, Entry, Button, Listbox, END, Scrollbar, Label, Frame, simpledialog
from cryptography.fernet import Fernet
import os

SERVER_IP = '92.113.144.62'  # IP serveur
PORT = 2122
HISTORY_DIR = "history"

os.makedirs(HISTORY_DIR, exist_ok=True)

class ChatClient:
    def __init__(self, master):
        self.master = master
        master.title("Encrypted Chat Client")

        # Layout
        main_frame = Frame(master)
        main_frame.pack(fill='both', expand=True)

        sidebar_frame = Frame(main_frame, width=150)
        sidebar_frame.pack(side='left', fill='y')
        Label(sidebar_frame, text="Recent Contacts").pack()
        self.contact_listbox = Listbox(sidebar_frame)
        self.contact_listbox.pack(fill='both', expand=True)
        self.contact_listbox.bind("<<ListboxSelect>>", self.on_contact_select)

        chat_frame = Frame(main_frame)
        chat_frame.pack(side='left', fill='both', expand=True)

        self.chat_text = Text(chat_frame, height=20, width=60, state='disabled')
        self.chat_text.pack(side='top', fill='both', expand=True)

        scrollbar = Scrollbar(chat_frame, command=self.chat_text.yview)
        scrollbar.pack(side='right', fill='y')
        self.chat_text['yscrollcommand'] = scrollbar.set

        entry_frame = Frame(chat_frame)
        entry_frame.pack(side='bottom', fill='x')

        self.message_entry = Entry(entry_frame, width=40)
        self.message_entry.pack(side='left', padx=5, pady=5)

        self.send_button = Button(entry_frame, text="Send", command=self.on_send)
        self.send_button.pack(side='left', padx=5, pady=5)

        self.recipient_entry = Entry(entry_frame, width=20)
        self.recipient_entry.pack(side='left', padx=5)
        self.recipient_entry.insert(0, "Recipient ID")

        # Load recent contacts
        self.recent_contacts = []
        for file in os.listdir(HISTORY_DIR):
            if file.endswith(".txt"):
                contact = file.replace(".txt","")
                self.recent_contacts.append(contact)
                self.contact_listbox.insert(END, contact)

        self.connect_to_server()
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def connect_to_server(self):
        self.USER_ID = simpledialog.askstring("User ID", "Enter your User ID:", parent=self.master)
        self.PASSWORD = simpledialog.askstring("Password", "Enter your password:", parent=self.master, show='*')

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((SERVER_IP, PORT))

        self.sock.recv(1024)  # "User ID: "
        self.sock.send(self.USER_ID.encode('utf-8'))
        self.sock.recv(1024)  # "Password: "
        self.sock.send(self.PASSWORD.encode('utf-8'))
        self.response = self.sock.recv(1024).decode('utf-8')
        self.append_message(f"[System] {self.response}")

    def append_message(self, msg):
        self.chat_text.config(state='normal')
        self.chat_text.insert(END, msg + "\n")
        self.chat_text.config(state='disabled')
        self.chat_text.see(END)

    def on_contact_select(self, event):
        selection = self.contact_listbox.curselection()
        if selection:
            self.recipient_entry.delete(0, END)
            self.recipient_entry.insert(0, self.contact_listbox.get(selection[0]))
            self.load_history(self.contact_listbox.get(selection[0]))

    def load_history(self, contact):
        self.chat_text.config(state='normal')
        self.chat_text.delete(1.0, END)
        history_file = os.path.join(HISTORY_DIR, f"{contact}.txt")
        if os.path.exists(history_file):
            with open(history_file, 'r') as f:
                self.chat_text.insert(END, f.read())
        self.chat_text.config(state='disabled')

    def on_send(self):
        msg = self.message_entry.get().strip()
        to_user = self.recipient_entry.get().strip()
        if not msg or not to_user:
            return
        self.send_message(msg, to_user)
        self.message_entry.delete(0, END)
        self.save_history(to_user, f"[Me] {msg}")

    def send_message(self, msg, to_user):
        key = Fernet.generate_key()
        f = Fernet(key)
        encrypted_message = f.encrypt(msg.encode('utf-8'))
        packet = {
            'key': key.decode('utf-8'),
            'message': encrypted_message.decode('utf-8'),
            'to': to_user
        }
        self.sock.send(json.dumps(packet).encode('utf-8'))

    def save_history(self, contact, msg):
        history_file = os.path.join(HISTORY_DIR, f"{contact}.txt")
        with open(history_file, 'a') as f:
            f.write(msg + "\n")
        if contact not in self.recent_contacts:
            self.recent_contacts.append(contact)
            self.contact_listbox.insert(END, contact)

    def receive_messages(self):
        while True:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                self.append_message(data.decode('utf-8'))
            except:
                break

if __name__ == "__main__":
    root = Tk()
    client = ChatClient(root)
    root.mainloop()
