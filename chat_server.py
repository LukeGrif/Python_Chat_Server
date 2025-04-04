
import socket
import threading

HOST = '127.0.0.1'
PORT = 5001

clients = []
lock = threading.Lock()

def recv_exactly(sock, size):
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
    except:
        pass
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
