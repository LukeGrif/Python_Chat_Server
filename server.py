"""
Filename: server.py
Author: Luke Griffin 21334538, Aaron Smith 21335168, Adam Jarvis 21339767, Nahid Islam 21337063
Description:
    Server backend for secure group chat:
    - Verifies client certificates and signed nonces
    - Forwards key shares and relays chat messages
    - Queues shares for offline clients
Date: 21-04-2025
"""

import socket
import threading
import pickle
import time

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding

from utils import (
    load_certs,
    save_certs,
    build_ca,
    generate_cert,
    KEY_SHARE,
    CHAT,
)

# Optional GUI hook; default logs to stdout
log_callback = print

def log(message):
    """Log server events via callback or stdout."""
    log_callback(f"[Server] {message}")

# Certificate initialization
try:
    certs = load_certs()
    log("Loaded existing certificates.")
except FileNotFoundError:
    log("Generating CA and entity certificates...")
    ca_key, ca_cert = build_ca()

    entities = ['A', 'B', 'C', 'S']  # Clients A, B, C and Server (S)
    certs = {'CA': ca_cert.public_bytes(x509.Encoding.PEM)}
    for eid in entities:
        name = 'Server' if eid == 'S' else f"Client{eid}"
        key, cert = generate_cert(name, ca_key, ca_cert)
        certs[eid] = {
            'key': key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ),
            'cert': cert.public_bytes(x509.Encoding.PEM),
        }
    save_certs(certs)
    log("Certificates generated and saved.")

# Server socket setup
HOST = '127.0.0.1'
PORT = 65432
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()
log(f"Server listening on {HOST}:{PORT}")

active_clients = {}
pending_shares = []

def deliver_pending(client_id, conn):
    """Send any queued KEY_SHARE messages to the newly connected client."""
    to_deliver = [ps for ps in pending_shares if ps[0] == client_id]
    for target, share in to_deliver:
        conn.sendall(pickle.dumps(share))
        log(f"Delivered pending share from {share['from']} to {target}")
        pending_shares.remove((target, share))

def handle_client(conn, addr):
    """Authenticate client and forward key shares or chat messages."""
    log(f"Connection from {addr}")
    try:
        raw = conn.recv(4096)
        auth = pickle.loads(raw)
        cert_bytes = auth['cert']
        signed_nonce = auth['signed_nonce']
        nonce = auth['nonce']
        timestamp = auth['timestamp']

        cert = x509.load_pem_x509_certificate(cert_bytes)
        pub_key = cert.public_key()
        ca_pub = x509.load_pem_x509_certificate(certs['CA']).public_key()

        # Verify CA signature and timestamp freshness
        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            asy_padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        if abs(time.time() - timestamp) > 5:
            conn.sendall(b'Timestamp not fresh')
            return

        # Verify signed nonce from client
        pub_key.verify(
            signed_nonce,
            f"{nonce}|{timestamp}".encode(),
            asy_padding.PKCS1v15(),
            hashes.SHA256()
        )
        conn.sendall(b'OK')

        # Register authenticated client
        client_id = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value[-1]
        active_clients[client_id] = conn
        log(f"Registered client {client_id}")

        # Deliver any previously pending shares
        deliver_pending(client_id, conn)

        # Main loop: handle requests and messages
        while True:
            data = conn.recv(4096)
            if not data:
                break
            try:
                text = data.decode()
                if text.startswith('GET_CERT'):
                    _, target = text.split()
                    cert_data = certs.get(target)
                    response = cert_data['cert'] if cert_data else b'ERROR'
                    conn.sendall(response)
                    log(f"Sent cert for {target}" if cert_data else f"Cert {target} not found")
                elif text == 'QUIT':
                    break
            except UnicodeDecodeError:
                msg = pickle.loads(data)
                mtype = msg.get('type')
                if mtype == KEY_SHARE:
                    dest = msg['to']
                    if dest in active_clients:
                        active_clients[dest].sendall(pickle.dumps(msg))
                        log(f"Forwarded key share from {msg['from']} to {dest}")
                    else:
                        pending_shares.append((dest, msg))
                        log(f"Queued share from {msg['from']} for {dest}")
                elif mtype == CHAT:
                    sender = msg['from']
                    log(f"Relaying chat from {sender}")
                    for cid, sock in active_clients.items():
                        if cid != sender:
                            try:
                                sock.sendall(pickle.dumps(msg))
                            except Exception:
                                log(f"Failed to send message to {cid}")
    except Exception as e:
        log(f"Error handling client: {e}")

def run_server():
    """Accept incoming connections and spawn handler threads indefinitely."""
    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == '__main__':
    run_server()
