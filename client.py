"""
Filename: client.py
Author: Luke Griffin
Description:
    Manages identity, X.509 certificate exchange, and session key establishment with other clients via a server.py.
    Once session key (Kabc) is securely shared, connects to chat_server.py and enters the AES-encrypted chat loop.
Date: 2025-04-07
Requirements Addressed:
    Requirement 1: No direct A,B,C communication
    Requirement 2: Certificate generation (X.509)
    Requirement 4: Authentication using certs
    Requirement 5: HMAC for key verification
    Requirement 6: Crypto algorithms — AES, RSA, HMAC
"""

import socket
import sys
import time
from cert_utils import generate_keypair, generate_certificate, serialize_cert, load_cert
from encryption_utils import encrypt_rsa, decrypt_rsa, compute_hmac, verify_hmac, generate_aes_key
from chat_client import chat_loop
from chat_client_ui import chat_loop

HOST = '127.0.0.1'
PORT = 5000
CHAT_PORT = 5001


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


def main(name):
    priv, pub = generate_keypair()
    cert = generate_certificate(name, pub, "CA", priv)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    print(f"[{name}] Connected to server")

    send_with_length(sock, name.encode())
    send_with_length(sock, serialize_cert(cert))

    if name == "A":
        print("[A] Waiting a moment for B and C to connect...")
        time.sleep(4)

        session_key = generate_aes_key()
        print(f"[A] Generated Kabc: {session_key.hex()}")

        for target in ["B", "C"]:
            print(f"[A] Requesting cert for {target}")
            send_with_length(sock, f"CERTREQ:{target}".encode())
            cert_data = recv_with_length(sock)
            if not cert_data or not cert_data.startswith(b"-----BEGIN CERTIFICATE-----"):
                raise ValueError(f"Invalid certificate received for {target}")
            target_cert = load_cert(cert_data)

            payload = name.encode() + b"||" + str(int(time.time())).encode() + b"||" + session_key
            mac = compute_hmac(session_key, payload)
            encrypted = encrypt_rsa(target_cert.public_key(), payload + b"||" + mac)
            print(f"[A] Sending session key to {target}...")
            send_with_length(sock, f"KEYTO:{target}".encode())
            send_with_length(sock, encrypted)
            print(f"[A] Sent encrypted session key to {target}")

        # A also joins the secure chat
        chat_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        chat_sock.connect(("127.0.0.1", CHAT_PORT))
        chat_loop(chat_sock, session_key, name)
    else:
        print(f"[{name}] Waiting for session key from A...")
        time.sleep(3)
        encrypted = recv_with_length(sock)
        try:
            decrypted = decrypt_rsa(priv, encrypted)
            parts = decrypted.split(b"||")
            if len(parts) != 4:
                raise ValueError("Invalid message format")
            sender, ts, key, mac = parts
            if abs(time.time() - int(ts)) > 20:
                raise ValueError(f"Time stamp is out of sync by {abs(time.time() - int(ts))} seconds - potential replay attack")
            valid = verify_hmac(key, b"||".join(parts[:3]), mac)
            print(f"[{name}] Received Kabc value: {key.hex()}")
            print(f"[{name}] Received Kabc from {sender.decode()}: {'OK' if valid else 'INVALID'}")

            # Start secure chat after key verification
            chat_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            chat_sock.connect(("127.0.0.1", CHAT_PORT))
            chat_loop(chat_sock, key, name)

        except Exception as e:
            print(f"[{name}] Failed to process key: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python client.py <A|B|C>")
        sys.exit(1)
    main(sys.argv[1])
