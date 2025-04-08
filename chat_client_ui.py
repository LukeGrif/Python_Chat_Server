"""
Filename: chat_client.py
Author: Luke Griffin
Description:
    Contains the client encrypted chat loop.
    Uses the shared AES session key (Kabc) to encrypt messages before sending and decrypt messages upon receiving.
    Interacts with the chat relay server but never exposes plaintext messages to it.
Requirements Addressed:
    Requirement 1: A, B, C must not communicate directly; all messages are routed via the server.
    Requirement 6: Uses AES to maintain confidentiality during chat.
Date: 2025-04-07

New Filename: chat_client_ui.py
Modified by Aaron to add a GUI for each client
Date: 2025-04-08
"""

import threading
from encryption_utils import encrypt_aes, decrypt_aes
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTextEdit, QLineEdit, QPushButton,
    QVBoxLayout, QWidget, QHBoxLayout
)

HOST = '127.0.0.1'
PORT = 5000

def send_with_length(sock, data):
    """
    Sends data prefixed with a 4-byte length header.
    Ensures complete message framing over TCP.

    Args:
        sock: Connected socket object
        data (bytes): Data to send
    """
    sock.send(len(data).to_bytes(4, 'big') + data)


def recv_with_length(sock):
    """
    Receives a complete data frame from a socket, respecting 4-byte length prefix.
    Args:
        sock: Connected socket
    Returns:
        bytes or None: Full message or None on disconnect
    """
    length_bytes = sock.recv(4)
    if not length_bytes:
        return None
    length = int.from_bytes(length_bytes, 'big')
    if length == 0:
        return None
    return sock.recv(length)

class ChatWindow(QMainWindow):
    """
    Creates a chat window GUI
    Args:
        sock: Connected socket
        session_key: the shared session key
        name: the client name
    """

    def __init__(self, sock, session_key, name):
        super().__init__()
        self.setWindowTitle(f"Secure Chat - {name}")
        self.setGeometry(100, 100, 600, 400)

        self.name = name
        self.session_key = session_key
        self.sock = sock
        self.stop_thread = False

        self.setup_ui()

    def setup_ui(self):
        self.chat_log = QTextEdit()
        self.chat_log.setReadOnly(True)

        self.message_input = QLineEdit()
        self.message_input.returnPressed.connect(self.send_message)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)

        input_layout = QHBoxLayout()
        input_layout.addWidget(self.message_input)
        input_layout.addWidget(self.send_button)

        layout = QVBoxLayout()
        layout.addWidget(self.chat_log)
        layout.addLayout(input_layout)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def append_message(self, msg):
        self.chat_log.append(msg)

    def send_message(self):
        text = self.message_input.text().strip()
        if not text: return
        msg = f"{self.name}: {text}"

        try:
            encrypted = encrypt_aes(self.session_key, msg.encode())
            send_with_length(self.sock, encrypted)
            self.message_input.clear()
            self.append_message(msg)
        except Exception as e:
            self.chat_log.append(f"[Send error] {e}")

def chat_loop(sock, session_key, name):
    """
    Starts the encrypted chat loop for a user.
    Handles both reading incoming messages and sending outgoing ones using AES encryption.
    Args:
        sock: Socket connected to chat relay server
        session_key (bytes): Shared AES key (Kabc)
        name (str): Client identifier (A, B, or C)
    """
    app = QApplication()
    window = ChatWindow(sock, session_key, name)
    window.show()

    def recv_thread():
        while True:
            try:
                msg = recv_with_length(sock)
                if msg:
                    plaintext = decrypt_aes(session_key, msg).decode()
                    window.append_message(plaintext)
                    print(f"{plaintext}")
            except Exception as e:
                print(f"[{name}] Error decrypting message: {e}")
                window.append_message(f"[{name}] Error decrypting message: {e}")
                break

    threading.Thread(target=recv_thread, daemon=True).start()

    print(f"[{name}] Entering secure chat. Type messages below:")
    window.append_message(f"[{name}] Entering secure chat. Type messages below:")

    app.exec()
