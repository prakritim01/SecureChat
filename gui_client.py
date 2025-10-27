# gui_client.py
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
import socket
import threading
import sys
import queue
from cryptography.exceptions import InvalidTag

# Import our crypto modules
import key_exchange as ke
import crypto_utils as cu
import protocol

# --- Configuration ---
# You can change these to connect to a different server
HOST = '127.0.0.1'
PORT = 9000

class SecureChatClient:
    def __init__(self, root, username):
        self.root = root
        self.username = username
        self.root.title(f"SecureChat - {self.username}")
        self.root.geometry("400x500")

        # --- Class members for state management ---
        self.client_socket = None
        self.session_key = None
        self.send_seq_num = 0
        self.recv_seq_num = -1
        self.incoming_queue = queue.Queue() # For thread-safe GUI updates

        # --- GUI Widgets ---
        self.message_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled')
        self.message_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.input_frame = tk.Frame(root)
        self.input_frame.pack(padx=10, pady=10, fill=tk.X)

        self.input_box = tk.Entry(self.input_frame, width=30)
        self.input_box.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.input_box.bind("<Return>", self.on_send_pressed)

        self.send_button = tk.Button(self.input_frame, text="Send", command=self.on_send_pressed)
        self.send_button.pack(side=tk.RIGHT)

        # --- Start network connection ---
        self.connect_to_server()
        
        # --- Start a periodic check for messages from the network thread ---
        self.root.after(100, self.process_incoming)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST, PORT))
            self.add_message_to_display("System", "Connected to server. Performing handshake...")
            
            # The handshake must run in a separate thread to avoid freezing the GUI
            handshake_thread = threading.Thread(target=self.perform_handshake, daemon=True)
            handshake_thread.start()

        except Exception as e:
            messagebox.showerror("Connection Failed", f"Could not connect to server at {HOST}:{PORT}\nError: {e}")
            self.on_closing()

    def perform_handshake(self):
        try:
            # 1. Generate & send our public key
            my_private_key, my_public_key = ke.generate_ecdh_key_pair()
            my_public_key_pem = ke.serialize_public_key(my_public_key)
            handshake_msg = protocol.create_handshake_message(self.username, my_public_key_pem)
            self.client_socket.send(handshake_msg)

            # 2. Receive peer's public key
            peer_response_bytes = self.client_socket.recv(4096)
            peer_msg = protocol.parse_message(peer_response_bytes)
            if not peer_msg or peer_msg["type"] != "handshake_pubkey":
                raise Exception("Handshake failed: Invalid response from peer.")
            
            peer_public_key = ke.deserialize_public_key(peer_msg["pubkey"])
            
            # --- GUI-based Fingerprint Verification ---
            my_fingerprint = ke.get_public_key_fingerprint(my_public_key_pem)
            peer_fingerprint = ke.get_public_key_fingerprint(peer_msg["pubkey"])
            
            # We must use 'root.after' to schedule the messagebox on the main GUI thread
            self.root.after(0, lambda: self.verify_fingerprint(my_fingerprint, peer_fingerprint, my_private_key, peer_public_key))

        except Exception as e:
            self.incoming_queue.put(("error", f"Handshake failed: {e}"))

    def verify_fingerprint(self, my_fingerprint, peer_fingerprint, my_private_key, peer_public_key):
        """Display fingerprints in a message box and get user confirmation."""
        verification_message = (
            "!!! MANUAL KEY VERIFICATION !!!\n\n"
            f"Your Fingerprint:\n{my_fingerprint}\n\n"
            f"Peer's Fingerprint:\n{peer_fingerprint}\n\n"
            "Do you trust this fingerprint?"
        )
        
        if messagebox.askyesno("Verify Fingerprint", verification_message):
            # 4. User trusted the key. Derive session key and start listening.
            shared_secret = ke.create_shared_secret(my_private_key, peer_public_key)
            self.session_key = ke.derive_session_key(shared_secret)
            self.add_message_to_display("System", "Handshake successful! Secure session established.")
            
            # Start the main message receiving loop
            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()
        else:
            self.add_message_to_display("System", "Handshake aborted by user. Disconnecting.")
            self.on_closing()

    def receive_messages(self):
        """Runs in a background thread, listening for messages."""
        while True:
            try:
                message_bytes = self.client_socket.recv(4096)
                if not message_bytes:
                    self.incoming_queue.put(("info", "Server connection lost."))
                    break

                msg = protocol.parse_message(message_bytes)
                if msg and msg.get("type") == "encrypted_msg":
                    # --- REPLAY PROTECTION ---
                    if msg["seq"] <= self.recv_seq_num:
                        self.incoming_queue.put(("warning", f"Replay attack detected! Discarded message (seq={msg['seq']})."))
                        continue
                    
                    # --- DECRYPTION ---
                    try:
                        plaintext = cu.decrypt_aes_gcm(msg["nonce"], msg["ciphertext"], msg["tag"], self.session_key)
                        self.recv_seq_num = msg["seq"] # Update only after successful decrypt
                        self.incoming_queue.put(("message", (msg['from'], plaintext.decode('utf-8'))))
                    except InvalidTag:
                        self.incoming_queue.put(("warning", f"Tampered message received from {msg['from']}! Discarding."))
            except Exception as e:
                self.incoming_queue.put(("info", f"Disconnected from server."))
                break
        
    def process_incoming(self):
        """Checks the queue for messages and updates the GUI."""
        while not self.incoming_queue.empty():
            try:
                msg_type, data = self.incoming_queue.get_nowait()
                if msg_type == "message":
                    sender, message = data
                    self.add_message_to_display(sender, message)
                elif msg_type == "info":
                    self.add_message_to_display("System", data)
                elif msg_type == "warning":
                    self.add_message_to_display("System", f"[WARNING] {data}")
                elif msg_type == "error":
                    messagebox.showerror("Error", data)
                    self.on_closing()
            except queue.Empty:
                pass
        self.root.after(100, self.process_incoming)

    def on_send_pressed(self, event=None):
        message_text = self.input_box.get()
        if not message_text:
            return
            
        if not self.session_key:
            messagebox.showwarning("Not Ready", "Secure session is not yet established. Please wait.")
            return

        try:
            # --- ENCRYPTION ---
            nonce, ciphertext, tag = cu.encrypt_aes_gcm(message_text.encode('utf-8'), self.session_key)
            encrypted_msg = protocol.create_encrypted_message(self.username, nonce, ciphertext, tag, self.send_seq_num)
            self.client_socket.send(encrypted_msg)
            
            self.add_message_to_display(self.username, message_text) # Display our own message
            self.input_box.delete(0, tk.END)
            self.send_seq_num += 1
        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send message: {e}")

    def add_message_to_display(self, sender, message):
        self.message_area.configure(state='normal')
        self.message_area.insert(tk.END, f"{sender}: {message}\n")
        self.message_area.configure(state='disabled')
        self.message_area.see(tk.END)

    def on_closing(self, event=None):
        if self.client_socket:
            self.client_socket.close()
        self.root.destroy()
        sys.exit(0)

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureChat - Login")
        self.root.geometry("300x150")
        
        self.username = None
        
        self.user_label = tk.Label(root, text="Username:")
        self.user_label.pack(pady=(10, 0))
        self.user_entry = tk.Entry(root)
        self.user_entry.pack(pady=5, padx=20, fill=tk.X)

        self.pass_label = tk.Label(root, text="Password:")
        self.pass_label.pack()
        self.pass_entry = tk.Entry(root, show="*")
        self.pass_entry.pack(pady=5, padx=20, fill=tk.X)
        self.pass_entry.bind("<Return>", self.on_login_pressed)

        self.login_button = tk.Button(root, text="Login", command=self.on_login_pressed)
        self.login_button.pack(pady=10)

    def on_login_pressed(self, event=None):
        username = self.user_entry.get()
        password = self.pass_entry.get()
        
        # This is the updated login logic:
        if username and password: # Simple check if fields are not empty
            self.username = username
            self.root.destroy()
        else:
            messagebox.showerror("Login Failed", "Username and password cannot be empty.")

# --- Main execution ---
if __name__ == "__main__":
    # Run the Login window
    login_root = tk.Tk()
    login_app = LoginWindow(login_root)
    login_root.mainloop()

    # If login was successful, run the main chat window
    if login_app.username:
        chat_root = tk.Tk()
        chat_app = SecureChatClient(chat_root, login_app.username)
        chat_root.mainloop()