import socket
import json
import hmac
import hashlib
import base64
import threading
import uuid
import signal
import sys

SECRET_KEY = b'supersecretkey'
MAX_MESSAGE_LENGTH = 1024  # Define a maximum message length

shutdown_flag = False  # Flag to control server shutdown
clients = []           # List of connected clients
conn_dict = {}         # Dictionary of client connections
client_info = {}       # Dictionary of client info

# Function to generate signature
def generate_signature(data, counter):
    message = f"{json.dumps(data)}{counter}".encode('utf-8')
    signature = hmac.new(SECRET_KEY, message, hashlib.sha256).digest()
    return base64.b64encode(signature).decode('utf-8')

# Function to verify signature
def verify_signature(data, counter, signature):
    expected_signature = generate_signature(data, counter)
    return hmac.compare_digest(signature, expected_signature)

# Handle each client connection in a separate thread
def handle_client(conn, addr, last_counter):
    print(f"Connected by {addr}")

    last_counter[addr] = 0
    name_assigned = False

    try:
        while not name_assigned:
            # Receive potential name from the client
            data = conn.recv(1024)
            if not data:
                print(f"Lost connection with {addr}")
                break

            message = json.loads(data.decode('utf-8'))
            client_name = message.get('data', '').strip()

            # Check if name is available
            normalized_name = client_name.lower()
            if normalized_name in [client['name'].lower() for client in client_info.values()]:
                response = {
                    "type": "name_response",
                    "available": False
                }
                conn.sendall(json.dumps(response).encode('utf-8'))
            else:
                client_info[addr] = {'name': client_name, 'id': str(uuid.uuid4())}
                clients.append(addr)
                conn_dict[addr] = conn

                response = {
                    "type": "name_response",
                    "available": True
                }
                conn.sendall(json.dumps(response).encode('utf-8'))
                name_assigned = True
                print(f"Client {addr} connected with name '{client_name}'")

        while True:
            if shutdown_flag:
                break

            data = conn.recv(1024)
            if not data:
                print(f"Lost connection with {addr}")
                break

            message = json.loads(data.decode('utf-8'))

            print(f"  Client {addr}")
            print(f"  {json.dumps(message, indent=2)}")

            if 'type' not in message or 'data' not in message or 'counter' not in message or 'signature' not in message:
                print(f"Invalid message structure from {addr}")
                continue

            if message['counter'] <= last_counter[addr]:
                print(f"Replay attack detected from {addr}. Counter: {message['counter']}, Last Counter: {last_counter[addr]}")
                continue

            if not verify_signature(message['data'], message['counter'], message['signature']):
                print(f"Invalid signature from {addr}")
                continue

            if message['data'] == "listclients":
                client_list = [
                    f"{client_info[client]['name']}, {client_info[client]['id']}"
                    for client in clients
                ]
                client_list_str = "List of clients:\n" + "\n".join(client_list)
                conn.sendall(client_list_str.encode('utf-8'))

            elif message['data'].startswith("message "):
                parts = message['data'].split(' ', 2)
                if len(parts) < 3:
                    print(f"Invalid private message format from {addr}")
                    continue
                
                recipient_name = parts[1]
                actual_message = parts[2]

                recipient_addr = None
                for client_addr, info in client_info.items():
                    if info['name'].lower() == recipient_name.lower():
                        recipient_addr = client_addr
                        break

                if recipient_addr:
                    private_message = f"{client_info[addr]['name']} to you: {actual_message}"
                    conn_dict[recipient_addr].sendall(private_message.encode('utf-8'))
                    print(f"Private message from {client_info[addr]['name']} to {recipient_name}: {actual_message}")
                else:
                    conn.sendall(f"User '{recipient_name}' not found.".encode('utf-8'))
            else:
                client_name = client_info[addr]['name']
                broadcast_message = f"{client_name}: {message['data']}"
                for client_addr, client_conn in conn_dict.items():
                    if client_addr != addr:
                        client_conn.sendall(broadcast_message.encode('utf-8'))
                print(f"Broadcast {broadcast_message}")

            last_counter[addr] = message['counter']

    except ConnectionResetError:
        print(f"Connection reset by {addr}")
    finally:
        if addr in clients:
            clients.remove(addr)
            del conn_dict[addr]
            del client_info[addr]
            conn.close()
            print(f"Client {addr} disconnected.")

# Function to gracefully shutdown the server
def shutdown_server(server_socket):
    global shutdown_flag
    shutdown_flag = True

    # Notify all connected clients that the server is shutting down
    for client_addr, client_conn in conn_dict.items():
        try:
            client_conn.sendall("Server is shutting down...".encode('utf-8'))
            client_conn.close()
        except Exception as e:
            print(f"Error disconnecting client {client_addr}: {e}")
    
    server_socket.close()
    print("Server shutdown complete.")

# Signal handler to catch shutdown signals (like Ctrl+C)
def signal_handler(sig, frame):
    print("\nShutting down server...")
    shutdown_server(server_socket)
    sys.exit(0)

# Start the server and accept multiple clients
def start_server():
    global server_socket
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('localhost', 12345))
        server_socket.listen(5)  # Allow up to 5 queued clients
        print("Server is listening...")
    except Exception as e:
        print(f"Error starting server: {e}")
        return

    last_counter = {}

    while not shutdown_flag:
        try:
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr, last_counter))
            client_thread.start()
        except Exception as e:
            if not shutdown_flag:
                print(f"Error accepting connection: {e}")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)  # Catch Ctrl+C
    start_server()
