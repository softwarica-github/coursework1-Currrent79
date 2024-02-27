import socket
import threading
import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox
import rsa

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Encrypted Chat App")
        
        # Increase key size for better security (this will make the encryption stronger but might be slower)
        self.public_key, self.private_key = rsa.newkeys(2048)
        self.public_partner_key = None
        self.connection = None

        # Improved UI layout
        self.init_ui()

    def init_ui(self):
        self.chat_log = scrolledtext.ScrolledText(self.root, state='disabled', height=20, width=70)
        self.chat_log.grid(row=0, column=0, columnspan=3, padx=10, pady=10)

        self.msg_entry = tk.Entry(self.root, width=50)
        self.msg_entry.grid(row=1, column=0, padx=10, pady=5)

        self.send_button = tk.Button(self.root, text="Send", command=self.send_message)
        self.send_button.grid(row=1, column=1, padx=10, pady=5)

        self.setup_button = tk.Button(self.root, text="Setup Connection", command=self.setup_connection)
        self.setup_button.grid(row=1, column=2, padx=10, pady=5)

    def setup_connection(self):
        choice = simpledialog.askstring("Setup Connection", "Host (1) or Join (2)?")
        if choice == "1":
            self.host_chat()
        elif choice == "2":
            self.join_chat()
        else:
            messagebox.showinfo("Info", "Invalid choice. Please enter 1 to host or 2 to join.")

    def host_chat(self):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", 9999))
            server.listen(1)
            self.log_message("Waiting for a connection...")
            client, _ = server.accept()
            self.connection = client
            self.exchange_keys(is_host=True)
        except Exception as e:
            messagebox.showerror("Hosting Failed", str(e))

    def join_chat(self):
        server_ip = simpledialog.askstring("Join Chat", "Enter host IP:")
        if server_ip:
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((server_ip, 9999))
                self.connection = client
                self.exchange_keys(is_host=False)
            except Exception as e:
                messagebox.showerror("Connection Error", f"Failed to connect to {server_ip}: {e}")
        else:
            messagebox.showinfo("Join Chat", "No IP address provided. Operation cancelled.")

    def exchange_keys(self, is_host):
        try:
            if is_host:
                self.connection.send(self.public_key.save_pkcs1('PEM'))
                partner_key = self.connection.recv(2048)  # Adjust buffer size if needed
                self.public_partner_key = rsa.PublicKey.load_pkcs1(partner_key)
            else:
                partner_key = self.connection.recv(2048)
                self.public_partner_key = rsa.PublicKey.load_pkcs1(partner_key)
                self.connection.send(self.public_key.save_pkcs1('PEM'))
            self.start_receiving_thread()
            self.log_message("Connection Established.")
        except Exception as e:
            messagebox.showerror("Key Exchange Failed", str(e))

    def send_message(self):
        message = self.msg_entry.get()
        if message and self.connection:
            try:
                encrypted_msg = rsa.encrypt(message.encode(), self.public_partner_key)
                self.connection.send(encrypted_msg)
                self.log_message("You: " + message, clear_entry=True)
            except Exception as e:
                messagebox.showerror("Send Failed", str(e))

    def start_receiving_thread(self):
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self):
        while True:
            try:
                msg = self.connection.recv(2048)
                if not msg:
                    break  # Connection closed
                decrypted_msg = rsa.decrypt(msg, self.private_key).decode()
                self.log_message("Partner: " + decrypted_msg)
            except Exception as e:
                messagebox.showerror("Connection Error", "The connection was lost. " + str(e))
                break

    def log_message(self, message, clear_entry=False):
        self.chat_log.config(state='normal')
        self.chat_log.insert('end', message + "\n")
        self.chat_log.config(state='disabled')
        self.chat_log.see('end')
        if clear_entry:
            self.msg_entry.delete(0, 'end')

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatApp(root)
    root.mainloop()

