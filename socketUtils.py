import socket
import json

def createUDPServerSocket(host, port):
    """Create and return a server socket using UDP."""
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverSocket.bind((host, port))
    return serverSocket

def createUDPClientSocket():
    """Create and return a client socket using UDP."""
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def sendObjUDP(sock, data, address):
    """Send a UDP JSON-encoded message to the socket."""
    message = json.dumps(data) 
    # sock.sendall(message.encode())  # Send the JSON string
    sock.sendto(message.encode(), address)

def sendObjTCP(sock, data):
    """Send a TCP JSON-encoded message to the socket."""
    message = json.dumps(data) 
    sock.sendall(message.encode())  # Send the JSON string

def recvObjTCP(sock):
    """Receive a TCP JSON-encoded message."""
    data = sock.recv(1024)
    return json.loads(data.decode())

def recvJsonMessage(sock):
    """Receive a JSON-encoded message from the socket."""
    data, clientAddress = sock.recvfrom(1024)  # Unpack data and address
    return json.loads(data.decode())

def recvObjUDP(sock):
    """Receive a JSON-encoded message from the socket."""
    data, clientAddress = sock.recvfrom(1024)  # Unpack data and address
    message = json.loads(data.decode())  # Decode and parse the JSON message
    return message, clientAddress

def sendResponse(sock, response, msg, address):
    sendObjUDP(sock, {"type": "RES", "response": response, "description": msg }, address)

