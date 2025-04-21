"""
Filename: server.py
Author: Luke Griffin 21334538, Aaron Smith 21335168, Adam Jarvis 21339767, Nahid Islam 21337063
Description:
    Server that facilitates secure group key exchange and messaging.
    Verifies client certificates and signed nonces
    Forwards encrypted key shares and chat messages
    Queues and delivers key shares if clients are not yet connected
    Does not see or access any plaintext messages
Date: 21-04-2025
"""

import socket, threading, pickle, time
from utils import (
    generate_cert, build_ca, save_certs, load_certs,
    KEY_SHARE, CHAT
)
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
from cryptography.hazmat.primitives import hashes

# === Optional GUI log callback ===
log_callback = print  # Default to print unless patched by GUI

def log(msg):
    log_callback(f"[Server] {msg}")

# === Certificate Initialization ===
try:
    certs = load_certs()
    log("Loaded certs from file.")
except FileNotFoundError:
    log("Generating CA and certs...")
    ca_key, ca_cert = build_ca()

    key_a, cert_a = generate_cert("ClientA", ca_key, ca_cert)
    key_b, cert_b = generate_cert("ClientB", ca_key, ca_cert)
    key_c, cert_c = generate_cert("ClientC", ca_key, ca_cert)
    key_s, cert_s = generate_cert("Server", ca_key, ca_cert)

    certs = {
        "CA": ca_cert.public_bytes(x509.Encoding.PEM),
        "A": {
            "key": key_a.private_bytes(x509.Encoding.PEM, x509.PrivateFormat.PKCS8, x509.NoEncryption()),
            "cert": cert_a.public_bytes(x509.Encoding.PEM),
        },
        "B": {
            "key": key_b.private_bytes(x509.Encoding.PEM, x509.PrivateFormat.PKCS8, x509.NoEncryption()),
            "cert": cert_b.public_bytes(x509.Encoding.PEM),
        },
        "C": {
            "key": key_c.private_bytes(x509.Encoding.PEM, x509.PrivateFormat.PKCS8, x509.NoEncryption()),
            "cert": cert_c.public_bytes(x509.Encoding.PEM),
        },
        "S": {
            "key": key_s.private_bytes(x509.Encoding.PEM, x509.PrivateFormat.PKCS8, x509.NoEncryption()),
            "cert": cert_s.public_bytes(x509.Encoding.PEM),
        },
    }

    save_certs(certs)
    log("Certificates generated and saved.")

# === Socket Setup ===
HOST, PORT = '127.0.0.1', 65432
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()
log("Listening on port 65432...")

active_clients = {}  # client_id → connection
pending_shares = []  # queued (to_id, share_obj)

def deliver_pending(client_id, conn):
    delivered = []
    for i, (target, share_obj) in enumerate(pending_shares):
        if target == client_id:
            conn.sendall(pickle.dumps(share_obj))
            log(f"Delivered queued share from {share_obj['from']} to {target}")
            delivered.append(i)
    for i in reversed(delivered):
        pending_shares.pop(i)

def handle_client(conn, addr):
    log(f"Connected by {addr}")
    try:
        data = conn.recv(4096)
        msg = pickle.loads(data)

        cert_bytes = msg['cert']
        signed_nonce = msg['signed_nonce']
        nonce = msg['nonce']
        timestamp = msg['timestamp']

        cert = x509.load_pem_x509_certificate(cert_bytes)
        pub_key = cert.public_key()
        ca_pub = x509.load_pem_x509_certificate(certs['CA']).public_key()

        ca_pub.verify(cert.signature, cert.tbs_certificate_bytes, asy_padding.PKCS1v15(), cert.signature_hash_algorithm)

        if abs(time.time() - timestamp) > 5:
            conn.sendall(b'Timestamp not fresh')
            return

        pub_key.verify(
            signed_nonce,
            f"{nonce}|{timestamp}".encode(),
            asy_padding.PKCS1v15(),
            hashes.SHA256()
        )

        conn.sendall(b'OK')
        client_id = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value[-1]
        active_clients[client_id] = conn
        log(f"Authenticated and registered client: {client_id}")

        # Deliver any pending shares to this client
        deliver_pending(client_id, conn)

        while True:
            data = conn.recv(4096)
            if not data:
                break
            try:
                decoded = data.decode()
                if decoded.startswith("GET_CERT"):
                    _, target_id = decoded.split()
                    if target_id in certs:
                        conn.sendall(certs[target_id]['cert'])
                        log(f"Sent certificate for {target_id}")
                    else:
                        conn.sendall(b'ERROR')
                elif decoded == "QUIT":
                    break
            except UnicodeDecodeError:
                obj = pickle.loads(data)
                if isinstance(obj, dict):
                    if obj.get('type') == KEY_SHARE:
                        to = obj['to']
                        if to in active_clients:
                            active_clients[to].sendall(pickle.dumps(obj))
                            log(f"Forwarded key share from {obj['from']} to {to}")
                        else:
                            pending_shares.append((to, obj))
                            log(f"Queued key share from {obj['from']} to {to} (not yet connected)")
                    elif obj.get('type') == CHAT:
                        sender = obj.get('from')
                        log(f"Relaying chat from {sender}")
                        for cid, sock in active_clients.items():
                            if cid != sender:
                                try:
                                    sock.sendall(pickle.dumps(obj))
                                except:
                                    log(f"Failed to send to {cid}")
    except Exception as e:
        log(f"Error: {e}")

def run_server():
    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == '__main__':
    run_server()