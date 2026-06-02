# tests/test_integration.py
import socket
import sys
import os
import json
import struct
import time

# Ensure we can import your crypto modules from the parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import key_exchange as ke
import crypto_utils as cu
import protocol

# --- TCP Framing Helpers ---
def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet: return None
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

def run_attack():
    print("[*] 😈 Attacker Script Started")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 9000))

    # 1. Login to Lobby as 'attacker'
    send_framed(sock, json.dumps({"type": "login", "username": "attacker"}).encode('utf-8'))
    
    # 2. Request chat with 'alice'
    send_framed(sock, json.dumps({"type": "chat_request", "from": "attacker", "to": "alice"}).encode('utf-8'))

    # 3. Handshake
    my_priv, my_pub = ke.generate_ecdh_key_pair()
    my_pub_pem = ke.serialize_public_key(my_pub)
    
    hs_msg = json.loads(protocol.create_handshake_message("attacker", my_pub_pem).decode('utf-8'))
    hs_msg["to"] = "alice"
    send_framed(sock, json.dumps(hs_msg).encode('utf-8'))

    print("[*] Sent malicious public key. Waiting for Alice's key...")

    # Wait for Alice's key
    peer_pub_pem = None
    while True:
        resp = recv_framed(sock)
        if not resp: return
        msg = protocol.parse_message(resp)
        if msg and msg["type"] == "handshake_pubkey":
            peer_pub_pem = msg["pubkey"]
            break

    print("[*] Received Alice's key. Deriving session key...")
    peer_pub = ke.deserialize_public_key(peer_pub_pem)
    shared_secret = ke.create_shared_secret(my_priv, peer_pub)
    session_key = ke.derive_session_key(shared_secret, my_pub_pem, peer_pub_pem)

    print("\n[!] IMPORTANT: GO TO ALICE'S TERMINAL AND TYPE 'yes' NOW!")
    print("[*] Sleeping for 10 seconds to give you time...")
    time.sleep(10)

    # --- ATTACK 1: VALID MESSAGE ---
    print("\n[*] 1. Sending Valid Message...")
    seq = 0
    aad = str(seq).encode('utf-8')
    nonce, combined_cipher = cu.encrypt_aes_gcm(b"Hello Alice, this is a legitimate message.", session_key, aad=aad)
    valid_msg = protocol.create_encrypted_message("attacker", nonce, combined_cipher, "", seq)
    vm = json.loads(valid_msg.decode('utf-8'))
    vm["to"] = "alice"
    send_framed(sock, json.dumps(vm).encode('utf-8'))
    time.sleep(1.5)

    # --- ATTACK 2: TAMPERED MESSAGE (Integrity Attack) ---
    print("[*] 2. Sending Tampered Message (Flipping a byte in ciphertext)...")
    seq = 1
    aad = str(seq).encode('utf-8')
    nonce2, combined_cipher2 = cu.encrypt_aes_gcm(b"This message will be tampered with.", session_key, aad=aad)
    
    # Tamper with the last byte of the GCM Auth Tag
    tampered_cipher = combined_cipher2[:-1] + bytes([combined_cipher2[-1] ^ 0xFF])
    
    tamper_msg = protocol.create_encrypted_message("attacker", nonce2, tampered_cipher, "", seq)
    tm = json.loads(tamper_msg.decode('utf-8'))
    tm["to"] = "alice"
    send_framed(sock, json.dumps(tm).encode('utf-8'))
    time.sleep(1.5)

    # --- ATTACK 3: REPLAY ATTACK ---
    print("[*] 3. Sending Replay Attack (Reusing seq=0)...")
    # We completely reuse the exact valid message from Attack 1
    send_framed(sock, json.dumps(vm).encode('utf-8'))
    time.sleep(1)

    print("\n[*] Attacks fired! Check Alice's terminal to see the defenses in action.")
    sock.close()

if __name__ == "__main__":
    run_attack()