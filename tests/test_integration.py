# tests/test_integration.py
import sys
import os
import socket
import json
import time

# Add the root project directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import key_exchange as ke
import crypto_utils as cu
import protocol

# --- Attacker's "Bob" Identity ---
BOB_USERNAME = "attacker_bob"
BOB_PRIV_KEY, BOB_PUB_KEY = ke.generate_ecdh_key_pair()
BOB_PUB_KEY_PEM = ke.serialize_public_key(BOB_PUB_KEY)
SESSION_KEY = None

def perform_attacker_handshake(sock):
    """Performs a 'valid' handshake to establish a session key."""
    global SESSION_KEY
    
    # 1. Send our (Bob's) public key
    handshake_msg = protocol.create_handshake_message(BOB_USERNAME, BOB_PUB_KEY_PEM)
    sock.send(handshake_msg)
    print("\n[ATTACKER] Sent public key.")

    # 2. Receive Alice's public key
    alice_response_bytes = sock.recv(4096)
    alice_msg = protocol.parse_message(alice_response_bytes)
    
    # --- THIS IS THE CORRECTED LINE ---
    if not alice_msg or alice_msg["type"] != "handshake_pubkey":
        print(f"[ATTACKER] Handshake failed. Expected 'handshake_pubkey', got: {alice_msg}")
        raise Exception("Handshake failed")
    # ---
    
    print("[ATTACKER] Received Alice's public key.")
    alice_public_key = ke.deserialize_public_key(alice_msg["pubkey"])

    # 3. Establish session key
    shared_secret = ke.create_shared_secret(BOB_PRIV_KEY, alice_public_key)
    SESSION_KEY = ke.derive_session_key(shared_secret)
    print(f"[ATTACKER] Session key established: {SESSION_KEY.hex()[:10]}...")
    
    # Wait 10 seconds to give the human user time to
    # type 'yes' in the real client's terminal.
    print("[ATTACKER] Waiting 10s for user to approve handshake in client...")
    time.sleep(10)


def test_tamper_attack(sock):
    """
    Test 1: Send a message with a tampered ciphertext.
    The client should detect this (InvalidTag) and reject it.
    """
    print("\n--- Running Tamper Attack ---")
    plaintext = b"This is a message... that will be... tampered!"
    
    nonce, ciphertext, tag = cu.encrypt_aes_gcm(plaintext, SESSION_KEY)
    
    # --- TAMPERING ---
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[5] ^= 0xFF # Flip all bits in the 5th byte
    print("[ATTACKER] Tampering with ciphertext...")
    # ---
    
    # Send the malicious message (seq=0)
    msg = protocol.create_encrypted_message(
        BOB_USERNAME, nonce, bytes(tampered_ciphertext), tag, 0
    )
    sock.send(msg)
    print("[ATTACKER] Sent tampered message (seq=0).")
    time.sleep(1) # Give client time to process

def test_replay_attack(sock):
    """
    Test 2: Send a valid message, then send it again.
    The client should accept the first and reject the second.
    """
    print("\n--- Running Replay Attack ---")
    plaintext = b"This is a valid message (seq=1)"
    
    nonce, ciphertext, tag = cu.encrypt_aes_gcm(plaintext, SESSION_KEY)
    
    # Send the valid message (seq=1)
    msg = protocol.create_encrypted_message(
        BOB_USERNAME, nonce, ciphertext, tag, 1
    )
    
    # --- ATTACK ---
    print("[ATTACKER] Sending valid message (seq=1)...")
    sock.send(msg)
    time.sleep(1) # Give client time to process
    
    print("[ATTACKER] RE-SENDING same message (seq=1)...")
    sock.send(msg) # Send the *exact same message*
    time.sleep(1)
    # ---

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(('127.0.0.1', 9000))
        
        # Step 1: Handshake (now includes a 10s pause)
        perform_attacker_handshake(sock)
        
        # Step 2: Run Tamper Test
        test_tamper_attack(sock)
        
        # Step 3: Run Replay Test
        test_replay_attack(sock)
        
        # Keep connection alive for a few more seconds
        print("\n[ATTACKER] Attacks sent. Waiting 3s for client to process...")
        time.sleep(3) 
        
        print("[ATTACKER] All tests complete.")
        
    except Exception as e:
        print(f"\n[ATTACKER] Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()