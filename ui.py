"""
Filename: server.py
Author: Luke Griffin 21334538, Aaron Smith 21335168, Adam Jarvis 21339767, Nahid Islam 21337063
Description:
    GUI launcher for the secure group chat system.
    Opens four windows: server log, and clients A, B, and C
    Each client authenticates, exchanges keys, and starts chat
    Provides user-friendly interfaces for real-time interaction
Date: 21-04-2025
"""

import sys
import threading
import time
import pickle
import socket
from PySide6.QtWidgets import (QApplication, QWidget, QTextEdit, QVBoxLayout,
                               QLineEdit, QPushButton, QLabel)
from PySide6.QtCore import Qt
from utils import aes_encrypt, aes_decrypt, hmac_digest, hmac_verify, load_certs, KEY_SHARE, CHAT
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import os

HOST, PORT = '127.0.0.1', 65432

class ServerWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(" Server Log")
        self.resize(400, 300)
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        layout = QVBoxLayout()
        layout.addWidget(self.log)
        self.setLayout(layout)

    def append_log(self, msg):
        self.log.append(msg)

class ClientWindow(QWidget):
    def __init__(self, client_id):
        super().__init__()
        self.client_id = client_id
        self.setWindowTitle(f" Client {client_id}")
        self.resize(400, 300)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.input_field = QLineEdit()
        self.send_button = QPushButton("Send")

        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"Client {client_id} Chat"))
        layout.addWidget(self.chat_display)
        layout.addWidget(self.input_field)
        layout.addWidget(self.send_button)
        self.setLayout(layout)

        self.send_button.clicked.connect(self.send_message)
        self.sock = None
        self.Kabc = None

        self.private_key = None
        self.public_keys = {}
        self.received_shares = {}

        threading.Thread(target=self.connect_and_run, daemon=True).start()

    def connect_and_run(self):
        try:
            self.chat_display.append(" Starting connection sequence...")

            certs = load_certs()
            cert = certs[self.client_id]['cert']
            key = certs[self.client_id]['key']
            self.private_key = serialization.load_pem_private_key(key, password=None)

            s = socket.socket()
            s.connect((HOST, PORT))
            self.sock = s

            nonce = os.urandom(16).hex()
            timestamp = time.time()
            msg = f"{nonce}|{timestamp}".encode()
            sig = self.private_key.sign(msg, padding.PKCS1v15(), hashes.SHA256())

            auth_msg = {'nonce': nonce, 'timestamp': timestamp, 'signed_nonce': sig, 'cert': cert}
            s.sendall(pickle.dumps(auth_msg))

            if s.recv(1024) != b'OK':
                self.chat_display.append(" Auth failed")
                return

            self.chat_display.append(" Authenticated with server")

            # Request public keys from others
            cert_data = load_certs()
            for peer_id in ['A', 'B', 'C']:
                if peer_id != self.client_id:
                    peer_cert = x509.load_pem_x509_certificate(cert_data[peer_id]['cert'])
                    self.public_keys[peer_id] = peer_cert.public_key()

            # Start listening BEFORE sending anything
            threading.Thread(target=self.receive_messages, daemon=True).start()

            self.chat_display.append(" Waiting for all clients to connect...")
            time.sleep(3)  # simple wait to ensure everyone connects

            key_share = os.urandom(16)
            self.received_shares['self'] = key_share
            self.chat_display.append(f" Generated own key share: {key_share.hex()}")

            for peer_id, pubkey in self.public_keys.items():
                encrypted = pubkey.encrypt(
                    key_share,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                 algorithm=hashes.SHA256(), label=None)
                )
                msg = {
                    'type': KEY_SHARE,
                    'from': self.client_id,
                    'to': peer_id,
                    'encrypted_share': encrypted
                }
                s.sendall(pickle.dumps(msg))
                self.chat_display.append(f" Sent encrypted key share to {peer_id}")

            self.compute_final_key()

        except Exception as e:
            import traceback
            self.chat_display.append(f" Fatal Error: {e}")
            self.chat_display.append(traceback.format_exc())

    def compute_final_key(self):
        if len(self.received_shares) == 3:
            shares = list(self.received_shares.values())
            self.Kabc = shares[0]
            for share in shares[1:]:
                self.Kabc = bytes(a ^ b for a, b in zip(self.Kabc, share))
            self.chat_display.append(f" Final session key Kabc = {self.Kabc.hex()}")

    def send_message(self):
        if not self.sock or not self.Kabc:
            return
        msg = self.input_field.text()
        self.input_field.clear()
        iv, ciphertext = aes_encrypt(msg.encode(), self.Kabc)
        tag = hmac_digest(self.Kabc, iv + ciphertext)
        obj = {'type': CHAT, 'from': self.client_id, 'iv': iv, 'ciphertext': ciphertext, 'hmac': tag}
        self.sock.sendall(pickle.dumps(obj))
        self.chat_display.append(f"You: {msg}")

    def receive_messages(self):
        while True:
            try:
                data = self.sock.recv(4096)
                obj = pickle.loads(data)

                if obj.get('type') == KEY_SHARE:
                    sender = obj['from']
                    encrypted = obj['encrypted_share']
                    try:
                        decrypted = self.private_key.decrypt(
                            encrypted,
                            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                         algorithm=hashes.SHA256(), label=None)
                        )
                        self.received_shares[sender] = decrypted
                        self.chat_display.append(f"⬅️ Received share from {sender}: {decrypted.hex()}")
                        self.chat_display.append(f" Keys so far: {list(self.received_shares.keys())}")
                        self.compute_final_key()
                    except Exception as e:
                        self.chat_display.append(f" Decryption error from {sender}: {e}")

                elif obj.get('type') == CHAT:
                    if not self.Kabc:
                        continue
                    sender = obj['from']
                    iv = obj['iv']
                    ciphertext = obj['ciphertext']
                    tag = obj['hmac']
                    if hmac_verify(self.Kabc, iv + ciphertext, tag):
                        msg = aes_decrypt(iv, ciphertext, self.Kabc).decode()
                        self.chat_display.append(f"{sender}: {msg}")
            except Exception as e:
                self.chat_display.append(f" Receive error: {e}")
                break

def start_server_gui(server_win):
    import server
    server.log_callback = server_win.append_log
    server.run_server()

def run_ui():
    app = QApplication(sys.argv)

    server_gui = ServerWindow()
    client_a = ClientWindow("A")
    client_b = ClientWindow("B")
    client_c = ClientWindow("C")

    server_gui.show()
    client_a.show()
    client_b.show()
    client_c.show()

    threading.Thread(target=start_server_gui, args=(server_gui,), daemon=True).start()

    sys.exit(app.exec())

if __name__ == "__main__":
    run_ui()
