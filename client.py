from socket import *
from threading import Thread, Timer
import sys
from socketUtils import createUDPClientSocket, recvJsonMessage, sendObjUDP, sendObjTCP, recvObjTCP
import time
import threading
import os


# Server would be running on the same host as Client
if len(sys.argv) != 2:
    print("\n===== Error usage, python3 client.py SERVER_PORT ======\n")
    exit(0)

serverHost = "127.0.0.1"
serverPort = int(sys.argv[1])
serverAddress = (serverHost, serverPort)

# define a socket for the client side
clientSocket = createUDPClientSocket()


username = None

# Start heartbeat in a separate thread
class HeartbeatThread(Thread):
    def __init__(self, clientSocket):
        Thread.__init__(self)
        self.clientSocket = clientSocket
        self.clientAlive = True

    def run(self):

        while True:
            time.sleep(2)

            # Send heartbeat
            if (self.clientAlive):
                sendServerReq({"type": "SYS", "action": "heartbeat", "arg": "", "username": username})
            else:
                self.stop()
                break
    def stop(self):
        self.clientAlive = False

        

class TCPUploadListenerThread(Thread):
    def __init__(self):
        super().__init__()
        # Create TCP connection
        self.serverSocket = socket(AF_INET, SOCK_STREAM)
        self.serverSocket.bind(('', 0))  # Bind to any available port
        self.port = self.serverSocket.getsockname()[1]  # Retrieve assigned port
        self.serverSocket.listen(5)
        self.running = True  # Control flag for stopping the thread

    def run(self):
        print(f"[UploadListener] Listening on port {self.port}")
        while self.running:
            # Use select to check for incoming connections without blocking indefinitely
            self.serverSocket.settimeout(1.0)
            try:
                peerSocket, clientAddress = self.serverSocket.accept()
                print(f"[UploadListener] Connection accepted from {clientAddress}")

                # Receive the JSON request from the client
                request = recvObjTCP(peerSocket)
                action = request.get("action")
                filename = request.get("arg")
                peerName = request.get("username")

                # Only handle download requests here
                if action == "download":
                    print(f"[UploadListener] Processing download request for '{filename}' by {peerName}")
                    self.handleUpload(peerSocket, filename, peerName)
                peerSocket.close()

            except timeout:
                continue  
            except Exception as e:
                if self.running:
                    print(f"[UploadListener Error] {e}")

    def handleUpload(self, clientSocket, filename, peerName):
        # Open the file and start sending it in chunks
        filePath = os.path.join(username, filename)

        with open(filePath, "rb") as file:
            print(f"[UploadListener] Sending file '{filename}' to {peerName}")
            while chunk := file.read(1024):
                clientSocket.sendall(chunk)
        print(f"[UploadListener] Completed file transfer of '{filename}'")

    def stop(self):
        self.running = False
        self.serverSocket.close()


class TCPDownloadThread(Thread):
    def __init__(self, peerName, peerPort, filename):
        Thread.__init__(self)
        self.peerName = peerName
        self.peerPort = peerPort
        self.filename = filename 
        
    def run(self):
        try:
            # Establish a TCP connection to the peer
            with socket(AF_INET, SOCK_STREAM) as peerSocket:
                peerSocket.connect((serverHost, self.peerPort))
                print(f"[Download] Connected to peer {self.peerName} to download '{self.filename}'")

                # Send request for the file
                sendObjTCP(peerSocket, {"type": "SYS", "action": "download", "arg": self.filename, "username": username})
                
                filePath = os.path.join(username, self.filename)
                with open(filePath, "wb") as file:
                    while True:
                        data = peerSocket.recv(1024)
                        if not data:
                            break
                        file.write(data)
                print(f"[Download] File '{self.filename}' downloaded successfully.")

            # Notify server of download completion
            sendServerReq({"type": "SYS", "action": "register_file", "username": username, "arg": self.filename})
            print(recvJsonMessage(clientSocket).get("description"))

        except Exception as e:
            print(f"[Error] Failed to download '{self.filename}' from {self.pee}: {e}")


def commandLoop(clientSocket):
    while heartbeatThread.clientAlive:
        message = input("\n===== Please type any message you want to send to server: =====\n")

        if message == "xit":
            print("Exiting client gracefully...")
            heartbeatThread.stop()
            uploadListenerThread.stop()
            break

        parts = message.split()
        action = parts[0]
        arg = parts[1] if len(parts) == 2 else ""

        sendServerReq({"type": "REQ", "action": action, "arg": arg, "username": username})
        
        msg = recvJsonMessage(clientSocket)
        if msg == "":
            print("[recv] Message from server is empty!")
        elif (msg.get("type") == "RES"):
            if action == "get" and msg.get("response") == "OK":
                peerInfo = msg.get("description")
                downloadThread = TCPDownloadThread(peerInfo["peer_name"], peerInfo["peer_port"], peerInfo["filename"])
                downloadThread.start()
            else:
                print("[recv]", msg.get("description"))

    clientSocket.close()


# Helpers
def sendServerReq(data):
    """Send a JSON-encoded message to the server using the provided address."""
    sendObjUDP(clientSocket, data, address=serverAddress)

def authenticate(clientSocket):
    """
    Handle authentication by sending username and password to the server,
    and waiting for the server's response.
    Keeps prompting until successful authentication.
    """
    # Request credentials from the user
    username = input("Enter username: ")
    password = input("Enter password: ")

    # Send credentials to the server
    sendServerReq({"type": "SYS", "action": "login", "arg": {"username": username, "password": password}})

    # Receive the authentication response from server
    response = recvJsonMessage(clientSocket)
    print(response.get("description"))

    if response.get("response") == "OK":
        return username
    else:
        return None



# Login
while username is None:
    print("[recv] You need to provide username and password to login")
    username = authenticate(clientSocket)

# Start threads
heartbeatThread = HeartbeatThread(clientSocket)
heartbeatThread.start()

uploadListenerThread = TCPUploadListenerThread()
uploadListenerThread.daemon = True
uploadListenerThread.start()

sendServerReq({"type": "SYS", "action": "allocate_port", "arg": uploadListenerThread.port, "username": username})
print("[recv]", recvJsonMessage(clientSocket).get("description"))

commandThread = threading.Thread(target=commandLoop, args=(clientSocket,))
commandThread.daemon = True
commandThread.start()

heartbeatThread.join()
commandThread.join()
uploadListenerThread.join()




