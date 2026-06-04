import os  # <-- ADDED THIS
import socket
import threading
import logging
import struct
import protocol  # Using our new protocol.py

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- TCP Framing Helpers ---
def recvall(sock, n):
    """Helper function to read exactly n bytes from the socket."""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def recv_framed(sock):
    """Reads a 4-byte length header, then reads the exact message payload."""
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen)

def send_framed(sock, message_bytes):
    """Prepends a 4-byte length header to the message before sending."""
    msglen = len(message_bytes)
    header = struct.pack('>I', msglen)
    sock.sendall(header + message_bytes)
# ---------------------------

class ChatServer:
    def __init__(self, host='0.0.0.0', port=9000):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((host, port))
        
        # { "username": { "socket": client_socket, "partner": None } }
        self.clients = {}
        self.client_lock = threading.Lock()
        
        logging.info(f"[*] Lobby Server listening on {host}:{port}")

    def start(self):
        self.server_socket.listen()
        while True:
            try:
                client_socket, addr = self.server_socket.accept()
                logging.info(f"[+] New connection from {addr}")
                thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                thread.daemon = True
                thread.start()
            except Exception as e:
                logging.error(f"[!] Error accepting connections: {e}")

    def handle_client(self, client_socket):
        username = None
        try:
            # --- 1. LOGIN ---
            login_msg_bytes = recv_framed(client_socket)
            if not login_msg_bytes:
                client_socket.close()
                return

            login_msg = protocol.parse_message(login_msg_bytes)
            
            if not login_msg or login_msg.get('type') != 'login':
                client_socket.close()
                return

            username = login_msg.get('username')
            
            with self.client_lock:
                if not username or username in self.clients:
                    client_socket.close()
                    return
                self.clients[username] = {"socket": client_socket, "partner": None}
                logging.info(f"[+] User '{username}' logged in.")
            
            # --- 2. BROADCAST LIST ---
            self.broadcast_user_list()

            # --- 3. MESSAGE LOOP ---
            while True:
                message_bytes = recv_framed(client_socket)
                if not message_bytes:
                    break
                self.process_message(username, message_bytes)

        except Exception as e:
            logging.error(f"[!] Error for '{username}': {e}")
        finally:
            self.cleanup_client(username)

    def process_message(self, sender_username, message_bytes):
        msg = protocol.parse_message(message_bytes)
        if not msg:
            return
        
        msg_type = msg.get('type')
        target_username = msg.get('to')

        with self.client_lock:
            # --- INTELLIGENT ROUTING FIX ---
            if not target_username:
                target_username = self.clients[sender_username].get("partner")

            # Update state for lobby commands
            if msg_type == 'chat_request' and target_username:
                self.clients[sender_username]["partner"] = target_username
                if target_username in self.clients:
                    self.clients[target_username]["partner"] = sender_username
            
            elif msg_type in ['chat_end', 'chat_reject'] and target_username:
                self.clients[sender_username]["partner"] = None
                if target_username in self.clients:
                    self.clients[target_username]["partner"] = None

            # --- RELAY ---
            if target_username and target_username in self.clients:
                try:
                    recipient_socket = self.clients[target_username]["socket"]
                    send_framed(recipient_socket, message_bytes)
                except Exception as e:
                    logging.error(f"[!] Relay failed: {e}")
            else:
                logging.warning(f"[!] Could not relay message from {sender_username} (Target: {target_username})")

    def broadcast_user_list(self):
        with self.client_lock:
            available_users = [u for u, d in self.clients.items() if d["partner"] is None]
            if not available_users: return
            
            message = protocol.create_user_list_message(available_users)
            for user in self.clients:
                try:
                    send_framed(self.clients[user]["socket"], message)
                except: pass

    def cleanup_client(self, username):
        if not username: return
        with self.client_lock:
            if username in self.clients:
                partner = self.clients[username].get("partner")
                data = self.clients.pop(username)
                try: data["socket"].close()
                except: pass

                if partner and partner in self.clients:
                    self.clients[partner]["partner"] = None
                    try:
                        end_msg = protocol.create_chat_end_message(username, partner)
                        send_framed(self.clients[partner]["socket"], end_msg)
                    except: pass
        self.broadcast_user_list()

if __name__ == "__main__":
    # --- ADDED RENDER DYNAMIC PORT LOGIC HERE ---
    HOST = '0.0.0.0'
    PORT = int(os.environ.get('PORT', 9000))
    server = ChatServer(host=HOST, port=PORT)
    server.start()