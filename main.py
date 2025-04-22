"""
Filename: main.py
Author: Luke Griffin 21334538, Aaron Smith 21335168, Adam Jarvis 21339767, Nahid Islam 21337063
Description:
    GUI launcher for the secure group chat system:
    - Opens four windows: server log, and clients A, B, C
    - Each client authenticates with the server, exchanges key shares, and chats securely
    - Real-time, encrypted group messaging with HMAC integrity checks
Date: 21-04-2025
"""

import os
import sys
import time
import socket
import pickle
import threading

from PySide6.QtWidgets import QApplication, QWidget, QTextEdit, QVBoxLayout, QLineEdit, QPushButton, QLabel
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from utils import aes_encrypt, aes_decrypt, hmac_digest, hmac_verify, load_certs, KEY_SHARE, CHAT

# Server connection settings
HOST = '127.0.0.1'
PORT = 65432

class ServerWindow(QWidget):
    """Window to display server log messages."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Server Log")
        self.resize(400, 300)
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        layout = QVBoxLayout()
        layout.addWidget(self.log_display)
        self.setLayout(layout)

    def append_log(self, message):
        """Append a message to the server log."""
        self.log_display.append(message)

class ClientWindow(QWidget):
    """GUI client that handles authentication, key exchange, and encrypted chat."""
    def __init__(self, client_id):
        super().__init__()
        self.client_id = client_id
        self.setWindowTitle(f"Client {client_id}")
        self.resize(400, 300)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.input_field = QLineEdit()
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)

        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"Client {client_id} Chat"))
        layout.addWidget(self.chat_display)
        layout.addWidget(self.input_field)
        layout.addWidget(self.send_button)
        self.setLayout(layout)

        self.sock = None
        self.private_key = None
        self.public_keys = {}
        self.received_shares = {}
        self.session_key = None

        threading.Thread(target=self._connect_and_run, daemon=True).start()

    def _log(self, message):
        """Append a line to the chat display."""
        self.chat_display.append(message)

    def _connect_and_run(self):
        """Authenticate with server, exchange key shares, and derive session key."""
        try:
            self._log("Starting connection sequence...")

            certs = load_certs()
            cert_pem = certs[self.client_id]['cert']
            key_pem = certs[self.client_id]['key']
            self.private_key = serialization.load_pem_private_key(key_pem, password=None)

            self.sock = socket.create_connection((HOST, PORT))

            nonce = os.urandom(16).hex()
            timestamp = time.time()
            payload = f"{nonce}|{timestamp}".encode()
            signature = self.private_key.sign(
                payload,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            auth_msg = {'nonce': nonce, 'timestamp': timestamp, 'signed_nonce': signature, 'cert': cert_pem}
            self.sock.sendall(pickle.dumps(auth_msg))

            if self.sock.recv(1024) != b'OK':
                self._log("Authentication failed.")
                return
            self._log("Authenticated with server.")

            all_certs = load_certs()
            for peer in ('A', 'B', 'C'):
                if peer != self.client_id:
                    peer_cert = x509.load_pem_x509_certificate(all_certs[peer]['cert'])
                    self.public_keys[peer] = peer_cert.public_key()

            threading.Thread(target=self._receive_messages, daemon=True).start()

            self._log("Waiting for all clients...")
            time.sleep(3)

            own_share = os.urandom(16)
            self.received_shares[self.client_id] = own_share
            self._log(f"Generated own key share: {own_share.hex()}")
            for peer, pubkey in self.public_keys.items():
                encrypted_share = pubkey.encrypt(
                    own_share,
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                msg = {'type': KEY_SHARE, 'from': self.client_id, 'to': peer, 'encrypted_share': encrypted_share}
                self.sock.sendall(pickle.dumps(msg))
                self._log(f"Sent key share to {peer}.")

            self._derive_session_key()

        except Exception as e:
            self._log(f"Fatal error: {e}")

    def _derive_session_key(self):
        """Combine received shares (XOR) to produce final group session key."""
        if len(self.received_shares) == 3:
            shares = list(self.received_shares.values())
            key = shares[0]
            for s in shares[1:]:
                key = bytes(a ^ b for a, b in zip(key, s))
            self.session_key = key
            self._log(f"Derived session key: {key.hex()}")

    def send_message(self):
        """Encrypt user input and send as CHAT message to server."""
        if not self.sock or not self.session_key:
            return
        plaintext = self.input_field.text()
        self.input_field.clear()
        iv, ct = aes_encrypt(plaintext.encode(), self.session_key)
        tag = hmac_digest(self.session_key, iv + ct)
        packet = {'type': CHAT, 'from': self.client_id, 'iv': iv, 'ciphertext': ct, 'hmac': tag}
        self.sock.sendall(pickle.dumps(packet))
        self._log(f"You: {plaintext}")

    def _receive_messages(self):
        """Listen for incoming KEY_SHARE and CHAT messages from server."""
        while True:
            try:
                raw = self.sock.recv(4096)
                msg = pickle.loads(raw)
                mtype = msg.get('type')
                if mtype == KEY_SHARE:
                    sender = msg['from']
                    try:
                        share = self.private_key.decrypt(
                            msg['encrypted_share'],
                            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                        )
                        self.received_shares[sender] = share
                        self._log(f"Received share from {sender}: {share.hex()}")
                        self._derive_session_key()
                    except Exception as e:
                        self._log(f"Failed to decrypt share from {sender}: {e}")
                elif mtype == CHAT and self.session_key:
                    sender = msg['from']
                    iv = msg['iv']
                    ct = msg['ciphertext']
                    tag = msg['hmac']
                    if hmac_verify(self.session_key, iv + ct, tag):
                        text = aes_decrypt(iv, ct, self.session_key).decode()
                        self._log(f"{sender}: {text}")
            except Exception as e:
                self._log(f"Receive error: {e}")
                break

def start_server_gui(server_window):
    """Launch the server backend in a thread and pipe logs to GUI."""
    import server as server_module
    server_module.log_callback = server_window.append_log
    server_module.run_server()

def run_ui():
    """Initialize application windows and start event loop."""
    app = QApplication(sys.argv)
    server_win = ServerWindow()
    clients = [ClientWindow(cid) for cid in ('A', 'B', 'C')]
    server_win.show()
    for client in clients:
        client.show()
    threading.Thread(target=start_server_gui, args=(server_win,), daemon=True).start()
    sys.exit(app.exec())

if __name__ == '__main__':
    run_ui()
