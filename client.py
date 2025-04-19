"""
Filename: client.py
Author: Luke Griffin
Description:
    Manages identity, X.509 certificate exchange, and session key establishment with other clients via a registration_server.py.
    Once session key (Kabc) is securely shared, connects to relay_server.py and enters the AES-encrypted chat loop.
Date: 2025-04-07
"""

import socket
import sys
import time
from utils_cert import generate_keypair, generate_ca, generate_certificate, serialize_cert, load_cert
from utils_encryption import encrypt_rsa, decrypt_rsa, compute_hmac, verify_hmac, generate_aes_key
from utils_ui import chat_loop

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
    ca_priv, ca_cert = generate_ca()  # Generate a shared CA
    priv, pub = generate_keypair()  # Generate keypair
    cert = generate_certificate(name, pub, ca_cert, ca_priv)  # Generate a CA-signed certificate

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Socket connection to registration_server.py
    sock.connect((HOST, PORT))  # Not the chat server yet

    print(f"[{name}] Connected to Server.py")

    send_with_length(sock, name.encode())
    send_with_length(sock, serialize_cert(cert))

    if name == "A":
        print("[A] Waiting a moment for B and C to connect...")
        time.sleep(4)

        session_key = generate_aes_key()  # Create Mutual Key Kabc
        print(f"[A] Generated Kabc: {session_key.hex()}")

        for target in ["B", "C"]:
            print(f"[A] Requesting cert for {target}")
            send_with_length(sock, f"CERTREQ:{target}".encode())  # Request Cert
            cert_data = recv_with_length(sock)  # Recieve Requested Cert
            if not cert_data or not cert_data.startswith(b"-----BEGIN CERTIFICATE-----"):  # Make sure it's not empty
                raise ValueError(f"Invalid certificate received for {target}")
            target_cert = load_cert(cert_data)

            # send timestamped session key to B || C
            payload = name.encode() + b"||" + str(int(time.time())).encode() + b"||" + session_key
            mac = compute_hmac(session_key, payload)  # HMAC for Integrity and Auth
            encrypted = encrypt_rsa(target_cert.public_key(), payload + b"||" + mac)  # Encrypts using target pub key

            print(f"[A] Sending session key to {target}...")
            send_with_length(sock, f"KEYTO:{target}".encode())
            send_with_length(sock, encrypted)
            print(f"[A] Sent encrypted session key to {target}")

        # A joins the secure chat
        chat_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        chat_sock.connect(("127.0.0.1", CHAT_PORT))
        chat_loop(chat_sock, session_key, name)  # A joins chat using session key

    else:
        print(f"[{name}] Waiting for session key from A...")
        time.sleep(3)
        encrypted = recv_with_length(sock)  # Encrypted Kabc
        try:
            decrypted = decrypt_rsa(priv, encrypted)  # Decrypt with private key
            parts = decrypted.split(b"||")  # Split
            if len(parts) != 4:
                raise ValueError("Invalid message format")
            sender, ts, session_key, mac = parts
            if abs(time.time() - int(ts)) > 20:
                raise ValueError(
                    f"Time stamp is out of sync by {abs(time.time() - int(ts))} seconds (potential replay attack)")
            valid = verify_hmac(session_key, b"||".join(parts[:3]), mac)  # Verify HMAC
            print(f"[{name}] Received Kabc value: {session_key.hex()}")
            print(f"[{name}] Received Kabc from {sender.decode()}: {'OK' if valid else 'INVALID'}")

            # Start secure chat after key verification
            chat_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            chat_sock.connect(("127.0.0.1", CHAT_PORT))
            chat_loop(chat_sock, session_key, name)  # Use recieved Session Key

        except Exception as e:
            print(f"[{name}] Failed to process key: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python client.py <A|B|C>")
        sys.exit(1)
    main(sys.argv[1])
