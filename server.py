# server.py
import socket
import threading
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def relay_messages(sender_socket, receiver_socket, sender_id):
    """
    Relays messages from a sender to a receiver.
    """
    try:
        while True:
            message = sender_socket.recv(4096)
            if not message:
                break # Client disconnected
            
            logging.info(f"Relaying message from Client {sender_id} to peer.")
            receiver_socket.send(message)
    except Exception as e:
        logging.error(f"[!] Error with client {sender_id}: {e}")
    finally:
        logging.info(f"[-] Client {sender_id} disconnected.")
        # Close both sockets when one disconnects
        sender_socket.close()
        receiver_socket.close()

def start_server(host='0.0.0.0', port=9000):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(2)
    logging.info(f"[*] Server listening on {host}:{port}")

    # --- Wait for both clients to connect BEFORE starting relay ---
    try:
        logging.info("Waiting for Client 1...")
        client1_sock, addr1 = server_socket.accept()
        logging.info(f"[+] Client 1 connected from {addr1}")

        logging.info("Waiting for Client 2...")
        client2_sock, addr2 = server_socket.accept()
        logging.info(f"[+] Client 2 connected from {addr2}")
        
        logging.info("[*] Both clients connected. Starting relay threads...")

        # Create two threads, one for each direction
        thread1 = threading.Thread(target=relay_messages, args=(client1_sock, client2_sock, 1))
        thread2 = threading.Thread(target=relay_messages, args=(client2_sock, client1_sock, 2))
        
        thread1.daemon = True
        thread2.daemon = True
        
        thread1.start()
        thread2.start()
        
        # Keep the main thread alive to wait for threads to finish
        thread1.join()
        thread2.join()

    except KeyboardInterrupt:
        logging.info("Server shutting down.")
    finally:
        server_socket.close()
        logging.info("Server closed.")

if __name__ == "__main__":
    start_server()