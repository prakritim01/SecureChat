# client.py
import socket
import threading
import argparse
import sys
import struct
import json
from cryptography.exceptions import InvalidTag

# Import our crypto functions
import key_exchange as ke
import crypto_utils as cu
import protocol

# Global state
SESSION_KEY = None
SEND_SEQ_NUM = 0
RECV_SEQ_NUM = -1 # Start at -1 so the first message (seq=0) is valid

# --- TCP Framing Helpers ---
def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def recv_framed(sock):
    raw_msglen = recvall(sock, 4)
    if not raw_msglen: return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen)

def send_framed(sock, message_bytes):
    msglen = len(message_bytes)
    header = struct.pack('>I', msglen)
    sock.sendall(header + message_bytes)
# ---------------------------

def receive_messages(client_socket):
    global SESSION_KEY, RECV_SEQ_NUM
    
    while True:
        try:
            message_bytes = recv_framed(client_socket)
            if not message_bytes:
                print("\n[!] Server connection lost.")
                break

            msg = protocol.parse_message(message_bytes)
            if not msg:
                continue

            if msg["type"] == "handshake_pubkey":
                print(f"\n[+] Received unexpected public key from {msg.get('from', 'unknown')}.")
                
            elif msg["type"] == "encrypted_msg":
                if SESSION_KEY is None:
                    print("\n[!] Received encrypted message but no session key established.")
                    continue
                
                # --- REPLAY PROTECTION & AAD ---
                seq_num = msg["seq"]
                if seq_num <= RECV_SEQ_NUM:
                    print(f"\n[!] Replay attack detected! Discarded message (seq={seq_num}).")
                    continue
                
                aad = str(seq_num).encode('utf-8')
                
                try:
                    combined_ciphertext = msg.get("combined_ciphertext", msg.get("ciphertext"))
                    plaintext = cu.decrypt_aes_gcm(msg["nonce"], combined_ciphertext, SESSION_KEY, aad=aad)
                    RECV_SEQ_NUM = seq_num # Update sequence number *after* successful decrypt
                    print(f"\n{msg['from']}: {plaintext.decode('utf-8')}\n> ", end="")
                    
                except InvalidTag:
                    print(f"\n[!] Received a tampered message (Invalid Tag / AAD mismatch)! Discarding.")
                except Exception as e:
                    print(f"\n[!] Decryption error: {e}")

        except Exception as e:
            print(f"\n[!] An error occurred in receive_messages: {e}")
            break
            
    print("Receive thread closing.")
    client_socket.close()


def send_messages(client_socket, username, target_username):
    global SESSION_KEY, SEND_SEQ_NUM
    
    print("\nType your messages and press Enter to send. Type 'exit' to quit.")
    try:
        while True:
            message_text = input("> ")
            if message_text.lower() == 'exit':
                break
                
            if SESSION_KEY is None:
                print("[!] Secure session not yet established. Please wait.")
                continue

            aad = str(SEND_SEQ_NUM).encode('utf-8')
            nonce, combined_ciphertext = cu.encrypt_aes_gcm(message_text.encode('utf-8'), SESSION_KEY, aad=aad)
            
            encrypted_msg = protocol.create_encrypted_message(
                username, nonce, combined_ciphertext, "", SEND_SEQ_NUM
            )
            
            msg_dict = json.loads(encrypted_msg.decode('utf-8'))
            msg_dict["to"] = target_username
            encrypted_msg = json.dumps(msg_dict).encode('utf-8')

            send_framed(client_socket, encrypted_msg)
            SEND_SEQ_NUM += 1 
            
    except (EOFError, KeyboardInterrupt):
        print("\n[!] You have left the chat.")
    except Exception as e:
        print(f"\n[!] Error sending message: {e}")
    finally:
        print("Send thread closing.")
        client_socket.close()


def perform_handshake(sock, username, target_username):
    global SESSION_KEY
    
    # 1. Generate our key pair
    my_private_key, my_public_key = ke.generate_ecdh_key_pair()
    my_public_key_pem = ke.serialize_public_key(my_public_key)

    # 2. Send our public key
    handshake_msg_raw = protocol.create_handshake_message(username, my_public_key_pem)
    msg_dict = json.loads(handshake_msg_raw.decode('utf-8'))
    msg_dict["to"] = target_username
    handshake_msg = json.dumps(msg_dict).encode('utf-8')

    # Firing initial handshake (May drop if peer isn't online yet)
    send_framed(sock, handshake_msg)
    print(f"[*] Waiting for {target_username} to connect and accept...")

    # 3. Receive peer's public key securely
    peer_public_key_pem = None
    
    while True:
        peer_response_bytes = recv_framed(sock)
        if not peer_response_bytes:
            print("[!] Connection closed while waiting for handshake.")
            return False
            
        peer_msg = protocol.parse_message(peer_response_bytes)
        if not peer_msg:
            continue
            
        # Ignore lobby noise
        if peer_msg["type"] in ["user_list", "login"]:
            continue
            
        # The peer just came online and paired with us! 
        # Resend our key to make sure they get it.
        if peer_msg["type"] == "chat_request":
            send_framed(sock, handshake_msg)
            continue
            
        if peer_msg["type"] == "handshake_pubkey":
            peer_public_key_pem = peer_msg["pubkey"]
            break
        else:
            print(f"[!] Handshake failed: Received unexpected '{peer_msg['type']}'.")
            return False
            
    peer_public_key = ke.deserialize_public_key(peer_public_key_pem)
    
    # --- PHASE 6: MANUAL FINGERPRINT VERIFICATION ---
    my_fingerprint = ke.get_public_key_fingerprint(my_public_key_pem)
    peer_fingerprint = ke.get_public_key_fingerprint(peer_public_key_pem)
    print("\n" + "="*50)
    print("!!! MANUAL KEY VERIFICATION !!!")
    print("This step prevents Man-in-the-Middle attacks.")
    print(f"\nYour Public Key Fingerprint:  {my_fingerprint}")
    print(f"Peer's Public Key Fingerprint: {peer_fingerprint}")
    print("\nCompare the 'Peer's Fingerprint' with the one your partner sees as 'Your Fingerprint'.")
    print("="*50)
    
    while True:
        confirm = input("Do you trust this fingerprint? (yes/no): ").strip().lower()
        if confirm == 'yes':
            print("[+] Fingerprint accepted. Proceeding.")
            break
        elif confirm == 'no':
            print("[!] Handshake aborted by user. Exiting.")
            return False
        else:
            print("[!] Please type 'yes' or 'no'.")
    # --- END PHASE 6 ---

    # 4. Create shared secret and derive session key (PFS Context)
    shared_secret = ke.create_shared_secret(my_private_key, peer_public_key)
    SESSION_KEY = ke.derive_session_key(shared_secret, my_public_key_pem, peer_public_key_pem)
    
    print("[+] Handshake successful! Secure session established.")
    return True


def main(host, port, username):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((host, port))
    except Exception as e:
        print(f"[!] Failed to connect to {host}:{port}. Error: {e}")
        return

    # To avoid case-sensitivity bugs, force everything to lowercase
    username = username.lower()
    
    print(f"[*] Connected to server. Logging in as '{username}'...")
    login_msg = json.dumps({"type": "login", "username": username}).encode('utf-8')
    send_framed(client_socket, login_msg)
    
    target_username = input("Enter the username of the person you want to chat with: ").strip().lower()
    
    chat_req_msg = json.dumps({"type": "chat_request", "from": username, "to": target_username}).encode('utf-8')
    send_framed(client_socket, chat_req_msg)

    # Perform handshake
    if not perform_handshake(client_socket, username, target_username):
        client_socket.close()
        return

    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.daemon = True
    receive_thread.start()

    send_messages(client_socket, username, target_username)
    
    print("Shutting down.")
    client_socket.close()
    sys.exit(0)

# THIS IS THE CRITICAL BLOCK THAT WAS MISSING
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure Chat Client")
    parser.add_argument('--host', default='127.0.0.1', help='Server host IP')
    parser.add_argument('--port', type=int, default=9000, help='Server port')
    parser.add_argument('--username', required=True, help='Your chat username')
    args = parser.parse_args()

    main(args.host, args.port, args.username)