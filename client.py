# client.py
import socket
import threading
import argparse
import sys
from cryptography.exceptions import InvalidTag

# Import our crypto functions
import key_exchange as ke
import crypto_utils as cu
import protocol

# Global state
SESSION_KEY = None
SEND_SEQ_NUM = 0
RECV_SEQ_NUM = -1 # Start at -1 so the first message (seq=0) is valid

def receive_messages(client_socket):
    global SESSION_KEY, RECV_SEQ_NUM
    
    while True:
        try:
            message_bytes = client_socket.recv(4096)
            if not message_bytes:
                print("\n[!] Server connection lost.")
                break

            msg = protocol.parse_message(message_bytes)
            if not msg:
                print("\n[!] Received malformed message. Discarding.")
                continue

            # Handle handshake messages (though unlikely at this stage)
            if msg["type"] == "handshake_pubkey":
                print(f"\n[+] Received unexpected public key from {msg['from']}.")
                
            # Handle encrypted data messages
            elif msg["type"] == "encrypted_msg":
                if SESSION_KEY is None:
                    print("\n[!] Received encrypted message but no session key established.")
                    continue
                
                # --- REPLAY PROTECTION ---
                seq_num = msg["seq"]
                if seq_num <= RECV_SEQ_NUM:
                    print(f"\n[!] Replay attack detected! Discarded message (seq={seq_num}).")
                    continue
                # ---
                
                try:
                    plaintext = cu.decrypt_aes_gcm(msg["nonce"], msg["ciphertext"], msg["tag"], SESSION_KEY)
                    RECV_SEQ_NUM = seq_num # Update sequence number *after* successful decrypt
                    print(f"\n{msg['from']}: {plaintext.decode('utf-8')}\n> ", end="")
                except InvalidTag:
                    print(f"\n[!] Received a tampered message from {msg['from']}! Discarding.")
                except Exception as e:
                    print(f"\n[!] Decryption error: {e}")

        except Exception as e:
            print(f"\n[!] An error occurred in receive_messages: {e}")
            break
            
    print("Receive thread closing.")
    client_socket.close()


def send_messages(client_socket, username):
    global SESSION_KEY, SEND_SEQ_NUM
    
    print("Type your messages and press Enter to send. Type 'exit' to quit.")
    try:
        while True:
            message_text = input("> ")
            if message_text.lower() == 'exit':
                break
                
            if SESSION_KEY is None:
                print("[!] Secure session not yet established. Please wait.")
                continue

            # Encrypt the message before sending
            nonce, ciphertext, tag = cu.encrypt_aes_gcm(message_text.encode('utf-8'), SESSION_KEY)
            
            # Create the JSON payload
            encrypted_msg = protocol.create_encrypted_message(
                username, nonce, ciphertext, tag, SEND_SEQ_NUM
            )
            client_socket.send(encrypted_msg)
            SEND_SEQ_NUM += 1 # Increment sequence number
            
    except (EOFError, KeyboardInterrupt):
        print("\n[!] You have left the chat.")
    except Exception as e:
        print(f"\n[!] Error sending message: {e}")
    finally:
        print("Send thread closing.")
        client_socket.close()


def perform_handshake(sock, username):
    global SESSION_KEY
    
    # 1. Generate our key pair
    my_private_key, my_public_key = ke.generate_ecdh_key_pair()
    my_public_key_pem = ke.serialize_public_key(my_public_key)

    # 2. Send our public key
    handshake_msg = protocol.create_handshake_message(username, my_public_key_pem)
    sock.send(handshake_msg)
    print("[+] Sent our public key. Waiting for peer...")

    # 3. Receive peer's public key
    peer_response_bytes = sock.recv(4096)
    peer_msg = protocol.parse_message(peer_response_bytes)
    
    if not peer_msg or peer_msg["type"] != "handshake_pubkey":
        print("[!] Handshake failed: Did not receive peer's public key.")
        return False
    
    peer_public_key_pem = peer_msg["pubkey"]
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

    # 4. Create shared secret and derive session key
    shared_secret = ke.create_shared_secret(my_private_key, peer_public_key)
    SESSION_KEY = ke.derive_session_key(shared_secret)
    
    print("[+] Handshake successful! Secure session established.")
    return True


def main(host, port, username):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((host, port))
    except Exception as e:
        print(f"[!] Failed to connect to {host}:{port}. Error: {e}")
        return

    # Perform handshake before starting chat threads
    if not perform_handshake(client_socket, username):
        client_socket.close()
        return

    # Start threads for sending and receiving
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.daemon = True
    receive_thread.start()

    # The main thread will handle sending messages
    send_messages(client_socket, username)
    
    # After send_messages (e.g., user types 'exit'), close the socket
    # which will also stop the receive_thread
    print("Shutting down.")
    client_socket.close()
    sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure Chat Client")
    parser.add_argument('--host', default='127.0.0.1', help='Server host IP')
    parser.add_argument('--port', type=int, default=9000, help='Server port')
    parser.add_argument('--username', required=True, help='Your chat username')
    args = parser.parse_args()

    main(args.host, args.port, args.username)