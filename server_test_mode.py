# server_test_mode.py
# A special server just for Phase 8 integration testing.
# This server pairs one client (the victim) with our attacker script.

import socket
import threading
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def relay_messages(sender_socket, receiver_socket, sender_id):
    try:
        while True:
            message = sender_socket.recv(4096)
            if not message:
                break
            logging.info(f"Relaying message from Client {sender_id} to peer.")
            receiver_socket.send(message)
    except Exception as e:
        logging.error(f"[!] Error with client {sender_id}: {e}")
    finally:
        logging.info(f"[-] Client {sender_id} disconnected.")
        sender_socket.close()
        receiver_socket.close()

def start_server(host='0.0.0.0', port=9000):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(2)
    logging.info(f"[*] TEST SERVER listening on {host}:{port}")

    try:
        logging.info("Waiting for Victim Client (e.g., Alice)...")
        victim_sock, addr1 = server_socket.accept()
        logging.info(f"[+] Victim client connected from {addr1}")

        logging.info("Waiting for Attacker Client (test script)...")
        attacker_sock, addr2 = server_socket.accept()
        logging.info(f"[+] Attacker client connected from {addr2}")
        
        logging.info("[*] Both clients connected. Starting relay threads...")

        thread1 = threading.Thread(target=relay_messages, args=(victim_sock, attacker_sock, "VICTIM"))
        thread2 = threading.Thread(target=relay_messages, args=(attacker_sock, victim_sock, "ATTACKER"))
        
        thread1.daemon = True
        thread2.daemon = True
        
        thread1.start()
        thread2.start()
        
        thread1.join()
        thread2.join()

    except KeyboardInterrupt:
        logging.info("Test server shutting down.")
    finally:
        server_socket.close()
        logging.info("Test server closed.")

if __name__ == "__main__":
    start_server()