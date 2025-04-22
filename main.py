# main.py

"""
Filename: main.py
Author: Luke Griffin 21334538, Aaron Smith 21335168, Adam Jarvis 21339767, Nahid Islam 21337063
Description:
    GUI launcher for the secure group chat:
    - Spins up server-log window + three client windows
    - Each client:
        • Authenticates via signed nonce + cert
        • Exchanges encrypted AES‑key shares over server
        • Derives a shared AES session key (XOR of shares)
        • Sends/receives AES‑CBC + HMAC‑SHA256–protected chat
Date: 21-04-2025
"""

import os
import sys
import time
import socket
import pickle
import threading

from PySide6.QtWidgets import (
    QApplication, QWidget, QTextEdit, QVBoxLayout,
    QLineEdit, QPushButton, QLabel
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from utils import aes_encrypt, aes_decrypt, hmac_digest, hmac_verify, load_certs, KEY_SHARE, CHAT

HOST, PORT = '127.0.0.1', 65432

class ServerWindow(QWidget):
    """Simple read‑only text view for server logs streamed in via callback."""
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
        """Called by server thread to push new log lines here."""
        self.log_display.append(message)

class ClientWindow(QWidget):
    """
    Each client instance:
      1) Loads its RSA cert/key for signing
      2) Connects & authenticates to server
      3) Receives peers’ public RSA keys
      4) Generates a random 16‑byte share and encrypts it to each peer
      5) Waits for other shares, XORs them → final 16‑byte AES key
      6) Sends & receives AES‑CBC+HMAC chat messages
    """
    def __init__(self, client_id):
        super().__init__()
        self.client_id     = client_id
        self.setWindowTitle(f"Client {client_id}")
        self.resize(400, 300)

        # -- UI setup --
        self.chat_display = QTextEdit(); self.chat_display.setReadOnly(True)
        self.input_field  = QLineEdit()
        self.send_button  = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"Client {client_id} Chat"))
        layout.addWidget(self.chat_display)
        layout.addWidget(self.input_field)
        layout.addWidget(self.send_button)
        self.setLayout(layout)

        # -- Network + crypto state --
        self.sock            = None
        self.private_key     = None
        self.public_keys     = {}  # map peer → RSA public key
        self.received_shares = {}  # map peer → decrypted share bytes
        self.session_key     = None

        # Kick off the background protocol
        threading.Thread(target=self._connect_and_run, daemon=True).start()

    def _log(self, text):
        """Append to chat display; used for status updates."""
        self.chat_display.append(text)

    def _connect_and_run(self):
        """Authenticate, exchange shares, and derive group key."""
        try:
            self._log("Connecting to server…")

            # Load this client’s cert+key for signing the nonce.
            certs   = load_certs()
            cert_pem= certs[self.client_id]['cert']
            key_pem = certs[self.client_id]['key']
            self.private_key = serialization.load_pem_private_key(key_pem, password=None)

            # TCP connect
            self.sock = socket.create_connection((HOST, PORT))

            # Build & sign nonce|timestamp
            nonce     = os.urandom(16).hex()
            timestamp = time.time()
            payload   = f"{nonce}|{timestamp}".encode()
            signature = self.private_key.sign(
                payload,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            # Send signed challenge + cert
            auth_msg = {
                'nonce': nonce,
                'timestamp': timestamp,
                'signed_nonce': signature,
                'cert': cert_pem
            }
            self.sock.sendall(pickle.dumps(auth_msg))

            # Await “OK” or fail
            if self.sock.recv(1024) != b'OK':
                self._log("Authentication failed.")
                return
            self._log("Authenticated successfully.")

            # Retrieve each peer’s RSA public key for key‑share encryption
            all_certs = load_certs()
            for peer in ('A','B','C'):
                if peer != self.client_id:
                    cert = x509.load_pem_x509_certificate(all_certs[peer]['cert'])
                    self.public_keys[peer] = cert.public_key()

            # Start listening thread before sending shares
            threading.Thread(target=self._receive_messages, daemon=True).start()

            # Little pause to ensure everyone has connected
            time.sleep(3)

            # Generate this client’s 16‑byte random share
            my_share = os.urandom(16)
            self.received_shares[self.client_id] = my_share
            self._log(f"Own share: {my_share.hex()}")

            # Encrypt & send that share to each other peer
            for peer, pub in self.public_keys.items():
                enc = pub.encrypt(
                    my_share,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                msg = {'type': KEY_SHARE, 'from': self.client_id, 'to': peer, 'encrypted_share': enc}
                self.sock.sendall(pickle.dumps(msg))
                self._log(f"Share sent to {peer}")

            # Try to combine all 3 shares via XOR → final AES key
            self._derive_session_key()

        except Exception as e:
            self._log(f"Protocol error: {e}")

    def _derive_session_key(self):
        """Once all 3 shares are in, XOR‑fold them to form the AES key."""
        if len(self.received_shares) == 3:
            shares = list(self.received_shares.values())
            key = shares[0]
            for s in shares[1:]:
                key = bytes(a ^ b for a, b in zip(key, s))
            self.session_key = key
            self._log(f"Session key established: {key.hex()}")

    def send_message(self):
        """AES‑CBC encrypt + HMAC and send chat text to the server."""
        if not self.session_key:
            return
        plaintext = self.input_field.text()
        self.input_field.clear()
        iv, ct = aes_encrypt(plaintext.encode(), self.session_key)
        mac    = hmac_digest(self.session_key, iv + ct)
        packet = {'type': CHAT, 'from': self.client_id, 'iv': iv, 'ciphertext': ct, 'hmac': mac}
        self.sock.sendall(pickle.dumps(packet))
        self._log(f"You: {plaintext}")

    def _receive_messages(self):
        """Continuously read KEY_SHARE or CHAT from server and process."""
        while True:
            try:
                blob = self.sock.recv(4096)
                msg  = pickle.loads(blob)
                mtype= msg.get('type')
                if mtype == KEY_SHARE:
                    # Decrypt incoming share
                    share = self.private_key.decrypt(
                        msg['encrypted_share'],
                        padding.OAEP(
                            mgf=padding.MGF1(hashes.SHA256()),
                            algorithm=hashes.SHA256(), label=None
                        )
                    )
                    sender = msg['from']
                    self.received_shares[sender] = share
                    self._log(f"Got share from {sender}: {share.hex()}")
                    self._derive_session_key()
                elif mtype == CHAT and self.session_key:
                    # Verify HMAC before decrypt
                    iv, ct, tag = msg['iv'], msg['ciphertext'], msg['hmac']
                    if hmac_verify(self.session_key, iv + ct, tag):
                        text = aes_decrypt(iv, ct, self.session_key).decode()
                        self._log(f"{msg['from']}: {text}")
            except Exception as e:
                self._log(f"Receive loop error: {e}")
                break

def start_server_gui(win):
    """Thread entry‑point: hook server.log_callback → GUI and run server."""
    import server
    server.log_callback = win.append_log
    server.run_server()

def run_ui():
    """Construct GUI windows and launch event loop."""
    app = QApplication(sys.argv)
    server_win = ServerWindow()
    clients    = [ClientWindow(c) for c in ('A','B','C')]
    server_win.show()
    for c in clients: c.show()
    threading.Thread(target=start_server_gui, args=(server_win,), daemon=True).start()
    sys.exit(app.exec())

if __name__ == '__main__':
    run_ui()
