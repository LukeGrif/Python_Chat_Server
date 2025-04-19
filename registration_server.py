"""
Filename: registration_server.py
Author: Luke Griffin
Description:
    Central authority facilitating mutual certificate verification and public key distribution between clients.
    It also forwards encrypted session keys from Client A to Clients B and C, without having access to the session key.
Date: 2025-04-07
"""

import socket
import threading
import time
from cryptography import x509
from cryptography.hazmat.primitives import serialization

HOST = '127.0.0.1'
PORT = 5000

clients = {}
certs = {}
lock = threading.Lock()


def recv_exactly(sock, size):
    data = b''
    while len(data) < size:
        packet = sock.recv(size - len(data))
        if not packet:
            raise ConnectionError("Socket connection broken")
        data += packet
    return data


def client_thread(conn, addr):
    """
    Handles a client connection. Receives and stores its certificate.
    Responds to certificate requests and forwards encrypted session keys.
    Args:
        conn: Client socket
        addr: Client IP/port
    """
    try:
        name_len = int.from_bytes(recv_exactly(conn, 4), 'big')
        name = recv_exactly(conn, name_len).decode()  # Recieve Name

        cert_len = int.from_bytes(recv_exactly(conn, 4), 'big')
        cert_pem = recv_exactly(conn, cert_len)  # Recieve Cert

        print(f"[SERVER] Received cert from {name} ({len(cert_pem)} bytes)")
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
            print(f"[SERVER] Parsed cert for {name}: CN={cert.subject}")
        except Exception as e:
            print(f"[SERVER] Failed to parse cert from {name}: {e}")
            conn.close()
            return

        with lock:
            clients[name] = conn
            certs[name] = cert

        print(f"[+] {name} connected from {addr} and cert stored")

        # Resoponds to 2 types of Req (CERTREQ & KEYTO)
        while True:
            data_len_bytes = conn.recv(4)  # Wait for message length 4
            if not data_len_bytes:
                break
            data_len = int.from_bytes(data_len_bytes, 'big')
            data = recv_exactly(conn, data_len)  # Reads full message
            # Cert being requested by A
            if data.startswith(b"CERTREQ:"):
                _, target = data.decode().split(":")
                for _ in range(10):  # Retries for 5 seconds to see get cert
                    with lock:
                        if target in certs:
                            print(f"[SERVER] Sending cert for {target} to {name}")
                            target_cert = certs[target].public_bytes(encoding=serialization.Encoding.PEM)
                            # Sends the pub key of target back to A
                            conn.send(len(target_cert).to_bytes(4, 'big') + target_cert)
                            break
                    time.sleep(0.5)
                else:
                    print(f"[SERVER] Failed to find cert for {target} after retries")
                    conn.send((0).to_bytes(4, 'big'))
            # A wants to send session key to B | C
            elif data.startswith(b"KEYTO:"):
                _, target = data.decode().split(":")
                msg_len = int.from_bytes(recv_exactly(conn, 4), 'big')
                msg = recv_exactly(conn, msg_len)
                with lock:
                    if target in clients:
                        print(f"[SERVER] Forwarding encrypted key from {name} to {target}")
                        clients[target].send(len(msg).to_bytes(4, 'big') + msg)
    except Exception as e:
        print(f"[!] Client error: {e}")
    finally:
        with lock:
            for k, v in list(clients.items()):
                if v == conn:
                    print(f"[SERVER] Disconnecting {k}")
                    del clients[k]
                    del certs[k]
        conn.close()


def main():
    print("[*] Starting server...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Listening on {HOST}:{PORT}")  # PORT - 5000
    while True:
        conn, addr = server.accept()
        threading.Thread(target=client_thread, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
