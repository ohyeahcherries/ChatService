import socket
import json
import hmac
import hashlib
import base64
import threading
from Crypto.Cipher import AES
import os

SECRET_KEY = b'supersecretkey'
AES_KEY = b'weakAESkey123456' 
MAX_MESSAGE_LENGTH = 1024  # Define a maximum message length
counter_lock = threading.Lock()  # Lock for thread-safe access to counter

# Function to generate signature
def generate_signature(data, counter):
    message = f"{json.dumps(data)}{counter}".encode('utf-8')
    signature = hmac.new(SECRET_KEY, message, hashlib.sha256).digest()
    return base64.b64encode(signature).decode('utf-8')

# Function to encrypt message
def encrypt_message(message):
    cipher = AES.new(AES_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

# Function to decrypt received message
def decrypt_message(encrypted_message):
    decoded = base64.b64decode(encrypted_message.encode('utf-8'))
    nonce = decoded[:16]
    tag = decoded[16:32]
    ciphertext = decoded[32:]
    cipher = AES.new(AES_KEY, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

def receive_messages(sock):
    while True:
        try:
            response = sock.recv(1024)
            if not response:
                break

            # Try to decode and parse as JSON
            try:
                message = json.loads(response.decode('utf-8'))

                # Check for name response
                if message.get("type") == "name_response":
                    if message.get("available"):
                        print(f"Name '{name}' accepted.")
                    else:
                        print(f"Name '{name}' is taken. Please choose another one.")
                
                # Check for private message
                elif message.get("type") == "private_message":
                    decrypted_message = decrypt_message(message["data"])
                    sender = message.get("sender", "Unknown")
                    print(f"\n{sender} to me: {decrypted_message}")
                
                # Fallback for other types of JSON messages
                else:
                    print(f"Server (JSON): {json.dumps(message, indent=2)}")

            except json.JSONDecodeError:
                # If it's not JSON, treat it as a plain text message
                plain_message = response.decode('utf-8')

                # Check if the server message is the name request
                if plain_message == "Please enter your name":
                    print("Enter your name:")
                else:
                    print("\n" + plain_message)

        except Exception as e:
            print(f"Error receiving message: {e}")
            break


def send_message(sock, message):
    with counter_lock:
        signed_message = {
            "type": "signed_data",
            "data": message,
            "counter": counter,
            "signature": generate_signature(message, counter)
        }
        sock.sendall(json.dumps(signed_message).encode('utf-8'))

def send_private_message(sock, recipient, message):
    with counter_lock:
        private_message = encrypt_message(message)
        signed_message = {
            "type": "private_message",
            "data": private_message,
            "recipient": recipient,  # Include the recipient name
            "counter": counter,
            "signature": generate_signature(private_message, counter)
        }
        sock.sendall(json.dumps(signed_message).encode('utf-8'))

def request_name(sock):
    while True:
        name = input("Enter your name: ")
        with counter_lock:
            signed_message = {
                "type": "signed_data",
                "data": name,
                "counter": counter,
                "signature": generate_signature(name, counter)
            }
            sock.sendall(json.dumps(signed_message).encode('utf-8'))

        # Wait for the server's response regarding name availability
        response = sock.recv(1024)
        message = json.loads(response.decode('utf-8'))

        if message.get("type") == "name_response":
            if message.get("available"):
                print(f"Name '{name}' accepted.")
                return name  # Return the accepted name
            else:
                print(f"Name '{name}' is taken. Please choose another one.")

# Connect to server
try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))
    client_socket.settimeout(10)  # Set a timeout of 10 seconds
except Exception as e:
    print(f"Error connecting to server: {e}")
    exit()
    

# Start a thread to listen for messages from the server
threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()

# Request and send the name
counter = 0
name = request_name(client_socket)

# Increment the counter after sending the name
with counter_lock:
    counter += 1

while True:
    try:
        message = input(f"{name}(me): ")

        # Check if it's a private message
        if message.startswith("message "):
            parts = message.split(' ', 2)  # Split into parts
            if len(parts) < 3:
                print("Invalid private message format. Use: message <recipient> <message>")
                continue
            
            recipient = parts[1]
            actual_message = parts[2]
            send_private_message(client_socket, recipient, actual_message)
        else:
            if len(message) > MAX_MESSAGE_LENGTH:
                print(f"Message too long. Limit is {MAX_MESSAGE_LENGTH} characters.")
                continue
            
            # Send message with the counter
            send_message(client_socket, message)

        # Increment the counter after sending each message
        with counter_lock:
            counter += 1
    except KeyboardInterrupt:
        print("\nExiting...")
        client_socket.close()
        break
