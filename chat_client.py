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
"""

import threading
from encryption_utils import encrypt_aes, decrypt_aes

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


def chat_loop(sock, session_key, name):
    """
    Starts the encrypted chat loop for a user.
    Handles both reading incoming messages and sending outgoing ones using AES encryption.
    Args:
        sock: Socket connected to chat relay server
        session_key (bytes): Shared AES key (Kabc)
        name (str): Client identifier (A, B, or C)
    """
    def recv_thread():
        while True:
            try:
                msg = recv_with_length(sock)
                if msg:
                    plaintext = decrypt_aes(session_key, msg).decode()
                    print(f"{plaintext}")
            except Exception as e:
                print(f"[{name}] Error decrypting message: {e}")
                break

    threading.Thread(target=recv_thread, daemon=True).start()

    print(f"[{name}] Entering secure chat. Type messages below:")
    while True:
        try:
            text = input()
            if not text.strip():
                continue
            msg = f"{name}: {text}".encode()
            encrypted = encrypt_aes(session_key, msg)
            send_with_length(sock, encrypted)
        except KeyboardInterrupt:
            print(f"[{name}] Exiting chat.")
            break
