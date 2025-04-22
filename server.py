# server.py

"""
Filename: server.py
Author: Luke Griffin 21334538, Aaron Smith 21335168, Adam Jarvis 21339767, Nahid Islam 21337063
Description:
    Server backend for secure group chat:
    - Verifies client certificates with a CA signature
    - Checks freshness of client nonces to prevent replay attacks
    - Forwards encrypted key‑share blobs or queues them if recipients are offline
    - Relays encrypted chat messages to all other connected clients
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
    load_certs,       # load or build the persistent cert/key store
    save_certs,
    build_ca,         # generate a self‑signed CA
    generate_cert,    # issue entity certificates
    KEY_SHARE, CHAT,  # message‑type constants
)

# If the GUI patches in its own logger, it replaces this;
# otherwise stdout via print() is used.
log_callback = print

# Track who’s online and any shares pending delivery
active_clients = {}       # client_id → socket
pending_shares = []       # [(to_client, share_message), …]

def log(message):
    """Unified hook for server logging (console or GUI)."""
    log_callback(f"[Server] {message}")

# --- Certificate setup: load existing or generate a new CA + entity certs ---
try:
    certs = load_certs()
    log("Loaded existing certificates.")
except FileNotFoundError:
    log("No cert store found—generating CA + entity certificates...")
    ca_key, ca_cert = build_ca()

    # Issue a cert for each client A/B/C plus the server (S).
    certs = {'CA': ca_cert.public_bytes(x509.Encoding.PEM)}
    for eid in ('A', 'B', 'C', 'S'):
        name = 'Server' if eid == 'S' else f"Client{eid}"
        key, cert = generate_cert(name, ca_key, ca_cert)
        certs[eid] = {
            'key': key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            'cert': cert.public_bytes(x509.Encoding.PEM),
        }
    save_certs(certs)
    log("Certificates generated and saved to certs.pkl.")

def deliver_pending(client_id, conn):
    """
    As soon as a client authenticates, deliver any queued
    KEY_SHARE messages that arrived while they were offline.
    """
    for (to_id, share) in pending_shares[:]:
        if to_id == client_id:
            conn.sendall(pickle.dumps(share))
            log(f"Delivered queued share from {share['from']} to {to_id}")
            pending_shares.remove((to_id, share))

def handle_client(conn, addr):
    """
    1) Read client’s signed nonce + cert, verify against CA and timestamp freshness.
    2) On success, reply b'OK', register client, deliver queued shares.
    3) Loop: either service 'GET_CERT' commands or proxy KEY_SHARE/CHAT blobs.
    """
    log(f"Incoming connection from {addr}")
    try:
        blob = conn.recv(4096)
        auth = pickle.loads(blob)

        # Extract signed nonce & client cert
        nonce      = auth['nonce']
        ts         = auth['timestamp']
        sig_nonce  = auth['signed_nonce']
        cert_bytes = auth['cert']
        cert       = x509.load_pem_x509_certificate(cert_bytes)
        pubkey     = cert.public_key()

        # Verify that the cert was signed by our CA
        ca_pub = x509.load_pem_x509_certificate(certs['CA']).public_key()
        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            asy_padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )

        # Timestamp check to avoid replays
        if abs(time.time() - ts) > 5:
            conn.sendall(b'Timestamp not fresh')
            return

        # Verify the client actually holds the private key
        pubkey.verify(
            sig_nonce,
            f"{nonce}|{ts}".encode(),
            asy_padding.PKCS1v15(),
            hashes.SHA256()
        )
        conn.sendall(b'OK')

        # Determine client ID (last char of CN, e.g. "ClientA")
        client_id = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value[-1]
        active_clients[client_id] = conn
        log(f"Authenticated and registered client {client_id}")

        # Send any shares queued up for this ID
        deliver_pending(client_id, conn)

        # Now handle GET_CERT, QUIT, or binary pickle messages
        while True:
            data = conn.recv(4096)
            if not data:
                break
            # Text commands (e.g. GET_CERT B)
            try:
                text = data.decode()
                if text.startswith('GET_CERT'):
                    _, target = text.split()
                    entry = certs.get(target)
                    reply = entry['cert'] if entry else b'ERROR'
                    conn.sendall(reply)
                    log(f"Sent cert for {target}" if entry else f"Cert {target} missing")
                elif text == 'QUIT':
                    break
            except UnicodeDecodeError:
                # Binary pickle: either KEY_SHARE or CHAT
                msg = pickle.loads(data)
                mtype = msg.get('type')
                if mtype == KEY_SHARE:
                    dest = msg['to']
                    if dest in active_clients:
                        active_clients[dest].sendall(pickle.dumps(msg))
                        log(f"Forwarded key share from {msg['from']} to {dest}")
                    else:
                        pending_shares.append((dest, msg))
                        log(f"Queued share from {msg['from']} for offline {dest}")
                elif mtype == CHAT:
                    sender = msg['from']
                    log(f"Relaying chat from {sender}")
                    # Forward to everyone else
                    for cid, sock in active_clients.items():
                        if cid != sender:
                            try:
                                sock.sendall(pickle.dumps(msg))
                            except:
                                log(f"Failed to relay chat to {cid}")
    except Exception as e:
        log(f"Error in client handler: {e}")
    finally:
        conn.close()
        active_clients.pop(client_id, None)
        log(f"Connection with {addr} closed")

def run_server():
    """Accept connections forever and spin up handler threads."""

    # --- Networking setup ---
    HOST, PORT = '127.0.0.1', 65432
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    log(f"Listening for clients on {HOST}:{PORT}…")

    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == '__main__':
    run_server()
