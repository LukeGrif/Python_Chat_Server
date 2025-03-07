import socket
import threading

# Define the IP and port for the server
SERVER_HOST = '127.0.0.1'  # Localhost
SERVER_PORT = 12345        # Port for the server

# Dictionary to store client connections
clients = {}

# Function to handle client connections
def handle_client(client_socket, client_name):
    """
    Handles communication between the server and a client.
    """
    while True:
        try:
            # Receive a message from the client
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break

            print(f"Received from {client_name}: {message}")

            # Forward the message to all other clients
            for name, socket in clients.items():
                if name != client_name:
                    socket.send(f"{client_name}: {message}".encode('utf-8'))

        except Exception as e:
            print(f"Error with {client_name}: {e}")
            break

    # Remove the client from the dictionary and close the connection
    del clients[client_name]
    client_socket.close()
    print(f"{client_name} has disconnected.")

# Function to start the server
def start_server():
    """
    Starts the chat server and listens for incoming connections.
    """
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"Server is listening on {SERVER_HOST}:{SERVER_PORT}")

    while True:
        # Accept a new connection
        client_socket, client_address = server_socket.accept()
        print(f"New connection from {client_address}")

        # Receive the client's name
        client_name = client_socket.recv(1024).decode('utf-8')
        print(f"{client_name} has joined the chat.")

        # Add the client to the dictionary
        clients[client_name] = client_socket

        # Start a new thread to handle the client
        threading.Thread(target=handle_client, args=(client_socket, client_name)).start()

# Function for clients to connect to the server
def connect_to_server(client_name):
    """
    Connects a client to the server.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))

    # Send the client's name to the server
    client_socket.send(client_name.encode('utf-8'))

    # Start a thread to receive messages from the server
    threading.Thread(target=receive_messages, args=(client_socket,)).start()

    # Send messages to the server
    while True:
        message = input(f"{client_name}: ")
        client_socket.send(message.encode('utf-8'))

# Function to receive messages from the server
def receive_messages(client_socket):
    """
    Receives messages from the server.
    """
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
        start_server()
    elif role in ["A", "B", "C"]:
        connect_to_server(role)
    else:
        print("Invalid role. Use 'server', 'A', 'B', or 'C'.")