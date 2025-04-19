"""
Filename: relay_server.py
Author: Luke Griffin 21334538, Aaron Smith 21335168, Adam Jarvis 21339767, Nahid Islam 21337063
Description:
    A  relay server that forwards encrypted messages between clients.
    It never decrypts or inspects messages, maintaining end-to-end encryption.
    Clients connect here after session key setup.
Date: 2025-04-07
"""

import socket
import threading

HOST = '127.0.0.1'
PORT = 5001

clients = []
lock = threading.Lock()


def recv_exactly(sock, size):
    """
    Reads exactly `size` bytes from a socket.
    Raises an error if connection breaks.
    """
    data = b''
    while len(data) < size:
        packet = sock.recv(size - len(data))
        if not packet:
            raise ConnectionError("Socket connection broken")
        data += packet
    return data


def recv_with_length(sock):
    length_bytes = recv_exactly(sock, 4)
    length = int.from_bytes(length_bytes, 'big')
    return recv_exactly(sock, length)


def handle_client(conn, addr):
    """
    Handles a new chat client connection.
    Forwards any encrypted message from this client to all others.

    Args:
        conn: Client socket
        addr: Client address
    """
    print(f"[+] Chat client connected from {addr}")
    with lock:
        clients.append(conn)
    try:
        while True:
            msg = recv_with_length(conn)
            print(msg)
            with lock:
                for client in clients:
                    if client != conn:
                        client.send(len(msg).to_bytes(4, 'big') + msg)
    except Exception as e:
        return print(f"Error handling_client: {e}")
    finally:
        with lock:
            clients.remove(conn)
        conn.close()
        print(f"[-] Chat client disconnected from {addr}")


def main():
    print("[*] Starting secure chat server...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Listening on {HOST}:{PORT}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
