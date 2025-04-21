"""
Filename: server.py
Author: Luke Griffin 21334538, Aaron Smith 21335168, Adam Jarvis 21339767, Nahid Islam 21337063
Description:
    Secure group chat client that:
    Authenticates with the server using signed nonces
    Exchanges encrypted key shares with peers
    Computes the shared session key (Kabc) using XOR
    Sends and receives AES+HMAC encrypted chat messages
    Displays messages in a graphical user interface
Date: 21-04-2025
"""

import socket, time, pickle, sys, os, threading
from utils import (
    aes_encrypt, aes_decrypt,
    hmac_digest, hmac_verify,
    load_certs,
    KEY_SHARE, CHAT
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from functools import reduce
from threading import Lock

if len(sys.argv) != 2 or sys.argv[1] not in ['A', 'B', 'C']:
    print("Usage: python client.py [A|B|C]")
    sys.exit(1)

client_id = sys.argv[1]
HOST, PORT = '127.0.0.1', 65432

certs = load_certs()
client_cert_bytes = certs[client_id]['cert']
client_key_bytes = certs[client_id]['key']
private_key = serialization.load_pem_private_key(client_key_bytes, password=None)

received_shares = {}
received_lock = Lock()
Kabc = None  # Final session key

# === Listen for messages ===
def listen_for_messages(sock):
    global Kabc
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            obj = pickle.loads(data)

            if obj.get('type') == KEY_SHARE:
                sender = obj['from']
                encrypted = obj['encrypted_share']
                try:
                    decrypted = private_key.decrypt(
                        encrypted,
                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                     algorithm=hashes.SHA256(),
                                     label=None)
                    )
                    with received_lock:
                        received_shares[sender] = decrypted
                        print(f"\n[Client {client_id}]  Received key share from {sender}: {decrypted.hex()}")
                        if len(received_shares) == 3 and 'self' in received_shares and Kabc is None:
                            keys = list(received_shares.values())
                            Kabc = reduce(lambda x, y: bytes(a ^ b for a, b in zip(x, y)), keys)
                            print(f"\n[Client {client_id}]  Final session key Kabc = {Kabc.hex()}")
                            print(f"[Client {client_id}] You may now start encrypted group chat.")
                            threading.Thread(target=chat_input_loop, args=(sock,), daemon=True).start()
                except Exception as e:
                    print(f"[Client {client_id}]  Failed to decrypt from {sender}: {e}")

            elif obj.get('type') == CHAT:
                sender = obj['from']
                iv = obj['iv']
                ciphertext = obj['ciphertext']
                tag = obj['hmac']
                if not Kabc or not hmac_verify(Kabc, iv + ciphertext, tag):
                    print(f"[Client {client_id}]  Message from {sender} failed HMAC check")
                    continue
                plaintext = aes_decrypt(iv, ciphertext, Kabc)
                print(f"\n[Client {client_id}]  {sender}: {plaintext.decode()}")

        except Exception as e:
            print(f"[Client {client_id}] Listener error: {e}")
            break

# === Input Loop ===
def chat_input_loop(sock):
    while True:
        msg = input(f"[Client {client_id}] > ")
        if not msg.strip():
            continue
        iv, ciphertext = aes_encrypt(msg.encode(), Kabc)
        tag = hmac_digest(Kabc, iv + ciphertext)
        msg_obj = {
            'type': CHAT,
            'from': client_id,
            'iv': iv,
            'ciphertext': ciphertext,
            'hmac': tag
        }
        sock.sendall(pickle.dumps(msg_obj))

# === Authentication ===
nonce = os.urandom(16).hex()
timestamp = time.time()
message = f"{nonce}|{timestamp}".encode()
signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

auth_msg = {
    'nonce': nonce,
    'timestamp': timestamp,
    'signed_nonce': signature,
    'cert': client_cert_bytes
}

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(pickle.dumps(auth_msg))

        if s.recv(1024) != b'OK':
            print("[Client] Authentication failed.")
            sys.exit(1)
        print(f"[Client {client_id}]  Authenticated with server")

        # === Request certs ===
        targets = ['A', 'B', 'C']
        targets.remove(client_id)
        public_keys = {}

        for target in targets:
            print(f"[Client {client_id}] Requesting cert for {target}")
            s.sendall(f"GET_CERT {target}".encode())

            cert_data = b""
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                cert_data += chunk
                if b"-----END CERTIFICATE-----" in cert_data:
                    break

            cert = x509.load_pem_x509_certificate(cert_data)
            ca_cert = x509.load_pem_x509_certificate(certs['CA'])
            ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            public_keys[target] = cert.public_key()
            print(f"[Client {client_id}]  Verified cert for {target}")

        # === Generate and send key share ===
        key_share = os.urandom(16)
        with received_lock:
            received_shares['self'] = key_share
        print(f"[Client {client_id}] Generated key share: {key_share.hex()}")

        threading.Thread(target=listen_for_messages, args=(s,), daemon=True).start()

        for target in public_keys:
            pubkey = public_keys[target]
            encrypted = pubkey.encrypt(
                key_share,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None)
            )
            msg = {
                'type': KEY_SHARE,
                'from': client_id,
                'to': target,
                'encrypted_share': encrypted
            }
            s.sendall(pickle.dumps(msg))
            print(f"[Client {client_id}]  Sent key share to {target}")

        print(f"[Client {client_id}] Waiting for key shares...")
        while True:
            time.sleep(1)

except Exception as e:
    print(f"[Client {client_id}]  Fatal error: {e}")
