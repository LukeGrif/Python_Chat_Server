import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import cryptography.x509 as x509
from cryptography.x509.oid import NameOID
import datetime

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

clients = {}
certificates = {}

# Generate client keypairs
def generate_client_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Generate certs
def generate_certificate(subject_name, issuer_name, subject_public_key, issuer_private_key, validity_days=365):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=validity_days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(subject_name)]), critical=False)
        .sign(issuer_private_key, hashes.SHA256())
    )
    return cert

# Function to handle client connections
def handle_client(client_socket, client_name):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            print(f"Received from {client_name}: {message}")
            #print(certificates) just checking certs are being stored
            for name, socket in clients.items():
                if name != client_name:
                    socket.send(f"{client_name}: {message}".encode('utf-8'))
        except Exception as e:
            print(f"Error with {client_name}: {e}")
            break
    del clients[client_name]
    client_socket.close()
    print(f"{client_name} has disconnected.")

# ChatServer class
class ChatServer:
    def start_server(self):
        self.private_key, self.public_key = generate_client_keys()
        self.cert = generate_certificate("ChatServer", "ChatServer", self.public_key, self.private_key)
        certificates["ChatServer"] = self.cert

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((SERVER_HOST, SERVER_PORT))
        self.server_socket.listen(5)
        (print(f"Server is listening on {SERVER_HOST}:{SERVER_PORT}"))

        while True:
            client_socket, client_address = self.server_socket.accept()
            print(f"New connection from {client_address}")

            # Receive client name with length prefix
            try:
                name_length_bytes = client_socket.recv(4)
                if not name_length_bytes:
                    print("Failed to receive name length")
                    client_socket.close()
                    continue
                name_length = int.from_bytes(name_length_bytes, 'big')
                client_name_bytes = client_socket.recv(name_length)
                client_name = client_name_bytes.decode('utf-8')
                print(f"Client name received: {client_name}")
            except Exception as e:
                print(f"Error receiving client name: {e}")
                client_socket.close()
                continue

            # Receive client cert with length prefix
            try:
                cert_length_bytes = client_socket.recv(4)
                if not cert_length_bytes:
                    print("Failed to receive certificate length")
                    client_socket.close()
                    continue
                cert_length = int.from_bytes(cert_length_bytes, 'big')
                print(f"Expecting certificate of length: {cert_length}")

                cert_pem = b""
                while len(cert_pem) < cert_length:
                    chunk = client_socket.recv(cert_length - len(cert_pem))
                    if not chunk:
                        raise Exception("Connection closed while receiving certificate")
                    cert_pem += chunk

                client_cert = x509.load_pem_x509_certificate(cert_pem)
                certificates[client_name] = client_cert
                print(f"Certificate received for {client_name}")
            except Exception as e:
                print(f"Error receiving certificate from {client_name}: {e}")
                client_socket.close()
                continue

            print(f"{client_name} has joined the chat.")
            clients[client_name] = client_socket
            threading.Thread(target=handle_client, args=(client_socket, client_name)).start()

# Function for clients to connect to the server
def connect_to_server(client_name):
    client_private_key, client_public_key = generate_client_keys()
    client_cert = generate_certificate(client_name, client_name, client_public_key, client_private_key)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))

    # Send client name with length prefix
    client_name_bytes = client_name.encode('utf-8')
    name_length = len(client_name_bytes)
    client_socket.send(name_length.to_bytes(4, 'big'))
    client_socket.send(client_name_bytes)

    # Send certs with length prefix
    cert_pem = client_cert.public_bytes(serialization.Encoding.PEM)
    cert_length = len(cert_pem)
    client_socket.send(cert_length.to_bytes(4, 'big'))
    client_socket.send(cert_pem)
    print(f"Sent certificate for {client_name}, length: {cert_length}")

    threading.Thread(target=receive_messages, args=(client_socket,)).start()
    while True:
        message = input(f"{client_name}: ")
        client_socket.send(message.encode('utf-8'))

# Function to receive messages from the server
def receive_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            print(message)
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

# Main function to start the server or client
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python chat.py <server|A|B|C>")
        sys.exit(1)

    role = sys.argv[1]
    if role == "server":
        server = ChatServer()
        server.start_server()
    elif role in ["A", "B", "C"]:
        connect_to_server(role)
    else:
        print("Invalid role. Use 'server', 'A', 'B', or 'C'.")