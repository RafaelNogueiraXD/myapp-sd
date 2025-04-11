#!/usr/bin/env python3
"""
A simple socket server that accepts connections from clients.
"""
import socket
import threading
import json
import time
from datetime import datetime

# Server configuration
HOST = '127.0.0.1'  # localhost
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)
MAX_CLIENTS = 5

# Connected clients
clients = []
client_lock = threading.Lock()

def get_timestamp():
    """Return current timestamp in human-readable format"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def broadcast_message(sender_id, message):
    """Send message to all connected clients except the sender"""
    with client_lock:
        for client in clients:
            # Don't send message back to sender
            if client['id'] != sender_id:
                try:
                    msg_data = {
                        'type': 'message',
                        'sender_id': sender_id,
                        'content': message,
                        'timestamp': get_timestamp()
                    }
                    client['socket'].sendall(json.dumps(msg_data).encode('utf-8') + b'\n')
                except:
                    # Client probably disconnected
                    pass

def update_client_list():
    """Send updated client list to all connected clients"""
    with client_lock:
        client_list = [{'id': client['id'], 'name': client['name']} for client in clients]
        for client in clients:
            try:
                msg_data = {
                    'type': 'client_list',
                    'clients': client_list,
                    'timestamp': get_timestamp()
                }
                client['socket'].sendall(json.dumps(msg_data).encode('utf-8') + b'\n')
            except:
                # Client probably disconnected
                pass

def client_handler(client_socket, client_id, client_addr):
    """Handle communication with a client"""
    client_name = f"Client-{client_id}"
    
    # Add client to the list
    with client_lock:
        clients.append({
            'id': client_id,
            'name': client_name,
            'socket': client_socket,
            'address': client_addr
        })
    
    print(f"[{get_timestamp()}] New connection: {client_name} ({client_addr[0]}:{client_addr[1]})")
    
    # Send welcome message to client
    welcome_msg = {
        'type': 'welcome',
        'message': f"Welcome to the server! You are connected as {client_name}.",
        'client_id': client_id,
        'timestamp': get_timestamp()
    }
    client_socket.sendall(json.dumps(welcome_msg).encode('utf-8') + b'\n')
    
    # Broadcast that a new client has joined
    system_msg = f"{client_name} has joined the server."
    broadcast_message('system', system_msg)
    
    # Update client list for everyone
    update_client_list()
    
    try:
        # Buffer for receiving data
        buffer = b''
        
        while True:
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
                    
                    if msg_data['type'] == 'message':
                        print(f"[{get_timestamp()}] Message from {client_name}: {msg_data['content']}")
                        broadcast_message(client_id, msg_data['content'])
                    
                    elif msg_data['type'] == 'name_change':
                        old_name = client_name
                        client_name = msg_data['name']
                        
                        # Update client name
                        with client_lock:
                            for client in clients:
                                if client['id'] == client_id:
                                    client['name'] = client_name
                                    break
                        
                        print(f"[{get_timestamp()}] Client {old_name} changed name to {client_name}")
                        broadcast_message('system', f"{old_name} changed their name to {client_name}")
                        update_client_list()
                    
                    # Add more message types as needed
                    
                except json.JSONDecodeError:
                    print(f"[{get_timestamp()}] Invalid JSON from {client_name}")
                except KeyError:
                    print(f"[{get_timestamp()}] Malformed message from {client_name}")
    except Exception as e:
        print(f"[{get_timestamp()}] Error handling client {client_name}: {e}")
    finally:
        # Remove client from list
        with client_lock:
            clients[:] = [c for c in clients if c['id'] != client_id]
        
        print(f"[{get_timestamp()}] Connection closed: {client_name}")
        client_socket.close()
        
        # Broadcast that the client has left
        broadcast_message('system', f"{client_name} has left the server.")
        update_client_list()

def main():
    """Main server function"""
    client_id_counter = 1
    
    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        # Bind socket to address and port
        server_socket.bind((HOST, PORT))
        
        # Listen for connections
        server_socket.listen(MAX_CLIENTS)
        print(f"[{get_timestamp()}] Server started on {HOST}:{PORT}")
        
        while True:
            # Accept connection
            client_socket, client_addr = server_socket.accept()
            
            # Start new thread for client
            client_thread = threading.Thread(
                target=client_handler,
                args=(client_socket, client_id_counter, client_addr)
            )
            client_thread.daemon = True
            client_thread.start()
            
            # Increment client ID counter
            client_id_counter += 1
    
    except KeyboardInterrupt:
        print(f"\n[{get_timestamp()}] Server shutting down...")
    except Exception as e:
        print(f"[{get_timestamp()}] Server error: {e}")
    finally:
        # Close server socket
        server_socket.close()
        print(f"[{get_timestamp()}] Server stopped")

if __name__ == "__main__":
    main()