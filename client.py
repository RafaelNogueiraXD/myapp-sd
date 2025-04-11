#!/usr/bin/env python3
"""
A simple socket client that connects to the server.
"""
import socket
import threading
import json
import sys
import time
from datetime import datetime
import os

# Server configuration
HOST = '127.0.0.1'  # localhost
PORT = 65432        # Server port

# Client state
client_id = None
client_name = None
connected = False
client_socket = None

def get_timestamp():
    """Return current timestamp in human-readable format"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def send_message(message_type, **kwargs):
    """Send a message to the server"""
    global client_socket
    
    if not connected or client_socket is None:
        print("[ERROR] Not connected to server")
        return False
    
    try:
        # Create message data
        msg_data = {
            'type': message_type,
            'timestamp': get_timestamp(),
            **kwargs
        }
        
        # Send message
        client_socket.sendall(json.dumps(msg_data).encode('utf-8') + b'\n')
        return True
    except Exception as e:
        print(f"[ERROR] Failed to send message: {e}")
        return False

def receive_messages():
    """Receive and process messages from the server"""
    global client_socket, client_id, client_name, connected
    
    # Buffer for receiving data
    buffer = b''
    
    try:
        while connected:
            # Receive data
            data = client_socket.recv(4096)
            if not data:
                break
            
            # Add to buffer and process any complete messages
            buffer += data
            
            # Process complete messages (assuming \n delimiter)
            while b'\n' in buffer:
                message, buffer = buffer.split(b'\n', 1)
                
                try:
                    # Parse JSON message
                    msg_data = json.loads(message.decode('utf-8'))
                    
                    if msg_data['type'] == 'welcome':
                        client_id = msg_data['client_id']
                        print(f"\n{msg_data['message']}")
                        print(f"Your client ID is: {client_id}")
                    
                    elif msg_data['type'] == 'message':
                        sender = msg_data['sender_id']
                        if sender == 'system':
                            print(f"\n[SYSTEM] {msg_data['content']}")
                        else:
                            # Find the sender's name in the client list
                            sender_name = f"Client-{sender}"  # Default if not found
                            print(f"\n[{sender_name}] {msg_data['content']}")
                    
                    elif msg_data['type'] == 'client_list':
                        clients = msg_data['clients']
                        print("\nConnected clients:")
                        for client in clients:
                            if client['id'] == client_id:
                                print(f" * {client['name']} (you)")
                            else:
                                print(f" * {client['name']}")
                    
                    # Add more message types as needed
                    
                except json.JSONDecodeError:
                    print(f"[ERROR] Invalid JSON from server")
                except KeyError as e:
                    print(f"[ERROR] Malformed message from server: missing key {e}")
                
                # Display prompt
                print("\n> ", end='', flush=True)
    
    except ConnectionResetError:
        print("\n[ERROR] Connection reset by server")
    except ConnectionAbortedError:
        print("\n[ERROR] Connection aborted")
    except Exception as e:
        if connected:  # Only print error if we haven't intentionally disconnected
            print(f"\n[ERROR] Error receiving messages: {e}")
    
    # If we get here, connection is lost
    if connected:
        connected = False
        print("\nDisconnected from server")
        sys.exit(1)

def connect_to_server():
    """Connect to the server"""
    global client_socket, connected
    
    # Create socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # Connect to server
        print(f"Connecting to server at {HOST}:{PORT}...")
        client_socket.connect((HOST, PORT))
        connected = True
        print("Connected to server")
        
        # Start thread to receive messages
        receive_thread = threading.Thread(target=receive_messages)
        receive_thread.daemon = True
        receive_thread.start()
        
        return True
    except ConnectionRefusedError:
        print("Error: Connection refused. Is the server running?")
    except Exception as e:
        print(f"Error connecting to server: {e}")
    
    # If we get here, connection failed
    client_socket.close()
    client_socket = None
    return False

def disconnect_from_server():
    """Disconnect from the server"""
    global client_socket, connected
    
    if connected and client_socket:
        try:
            # Close socket
            connected = False
            client_socket.close()
            print("Disconnected from server")
        except Exception as e:
            print(f"Error disconnecting from server: {e}")
    
    client_socket = None

def print_help():
    """Print help information"""
    print("\nAvailable commands:")
    print("  /help               - Show this help message")
    print("  /quit, /exit        - Disconnect and exit")
    print("  /name <new_name>    - Change your display name")
    print("  /list               - List connected clients")
    print("  /clear              - Clear the screen")
    print("  <message>           - Send a message to all clients")

def main():
    """Main client function"""
    global client_name
    
    print("Simple Chat Client")
    print("-----------------")
    
    # Connect to server
    if not connect_to_server():
        return
    
    print_help()
    
    try:
        while connected:
            # Get user input
            user_input = input("\n> ")
            
            # Process commands
            if user_input.lower() in ['/quit', '/exit']:
                break
            
            elif user_input.lower() == '/help':
                print_help()
            
            elif user_input.lower().startswith('/name '):
                new_name = user_input[6:].strip()
                if new_name:
                    client_name = new_name
                    send_message('name_change', name=new_name)
                    print(f"Name changed to: {new_name}")
                else:
                    print("Error: Name cannot be empty")
            
            elif user_input.lower() == '/list':
                # Server will send client list in response
                send_message('get_client_list')
            
            elif user_input.lower() == '/clear':
                # Clear screen based on OS
                if sys.platform == 'win32':
                    os.system('cls')
                else:
                    os.system('clear')
            
            # Regular message
            elif user_input:
                send_message('message', content=user_input)
    
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Disconnect from server
        disconnect_from_server()

if __name__ == "__main__":
    main()