
import socket
import sys
import threading
import time
from cert_utils import generate_keypair, generate_certificate, serialize_cert, load_cert
from encryption_utils import encrypt_rsa, decrypt_rsa, compute_hmac, verify_hmac, generate_aes_key, encrypt_aes, decrypt_aes

HOST = '127.0.0.1'
PORT = 5000

def send_with_length(sock, data):
    sock.send(len(data).to_bytes(4, 'big') + data)

def recv_with_length(sock):
    length_bytes = sock.recv(4)
    if not length_bytes:
        return None
    length = int.from_bytes(length_bytes, 'big')
    if length == 0:
        return None
    return sock.recv(length)

def chat_loop(sock, session_key, name):
    def recv_thread():
        while True:
            try:
                msg = recv_with_length(sock)
                if msg:
                    plaintext = decrypt_aes(session_key, msg).decode()
                    print(f"{plaintext}")
            except Exception as e:
                print(f"[{name}] Error decrypting message: {e}")
                break

    threading.Thread(target=recv_thread, daemon=True).start()

    print(f"[{name}] Entering secure chat. Type messages below:")
    while True:
        try:
            text = input()
            if not text.strip():
                continue
            msg = f"{name}: {text}".encode()
            encrypted = encrypt_aes(session_key, msg)
            send_with_length(sock, encrypted)
        except KeyboardInterrupt:
            print(f"[{name}] Exiting chat.")
            break
