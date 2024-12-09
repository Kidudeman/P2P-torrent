from threading import Thread
import sys
from socketUtils import createUDPServerSocket, recvObjUDP, sendResponse
import time
from threading import Timer
import socket

activePeers = {}
publishedFiles = {}

# acquire server host and port from command line parameter
if len(sys.argv) != 2:
    print("\n===== Error usage, python3 UDPServer.py SERVER_PORT ======\n")
    exit(0)
serverHost = "127.0.0.1"
serverPort = int(sys.argv[1])
serverSocket = createUDPServerSocket(serverHost, serverPort)

def loadCredentials(filename='credentials.txt'):
    """
    Load credentials from a file and return them as a dictionary.
    Format expected: each line has 'username password'
    """
    credentials = {}
    try:
        with open(filename, 'r') as file:
            for line in file:
                user, pwd = line.strip().split()
                credentials[user] = pwd
    except FileNotFoundError:
        print(f"Error: {filename} not found.")
        exit(1)
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        exit(1)
    return credentials


class ClientThread(Thread):
    def __init__(self):
        Thread.__init__(self)
        
    def run(self):
        while True:
            msg, clientAddress = recvObjUDP(serverSocket)
            if msg == '':
                # self.clientAlive = False
                print("===== the user disconnected - ", clientAddress)
                break

            action = msg.get("action")
            type = msg.get("type")

            # system requests
            if type == "SYS":
                if action == "login":
                    self.processLogin(clientAddress, msg.get("arg").get("username"), msg.get("arg").get("password"))
                elif action == "heartbeat":
                    print(f"[recv] HBT from {msg.get('username')}")
                    self.processHeartbeat(msg.get('username'))
                elif action == "allocate_port":
                    self.registerPeerPort(msg.get("username"), msg.get("arg"), clientAddress)
                elif action == "register_file":
                    self.processPublishFile(msg.get("arg"), msg.get("username"), clientAddress)
                
            # user terminal command requests
            elif type == "REQ":
                print(f"[recv] {action} request from {msg.get('username')}")

                if action == "get":
                    self.processGetFile(msg.get("arg"), msg.get("username"), clientAddress)
                elif action == "lap":
                    self.processLap(msg.get("username"), clientAddress)
                elif action == "pub":
                    self.processPublishFile(msg.get("arg"), msg.get("username"), clientAddress)
                elif action == "lpf":
                    self.listPublishedFiles(msg.get("username"), clientAddress)
                elif action == "sch":
                    self.processSearchFiles(msg.get("arg"), msg.get("username"), clientAddress)
                elif action == "unp":
                    self.processUnpublishFile(msg.get("arg"), msg.get("username"), clientAddress)
                else:
                    print("[recv] " + action)
                    print("[send] Cannot understand this message")
                    sendResponse(serverSocket, "ERR", "Cannot understand this message")
            else:
                print("[recv] " + type)
                print("[send] Cannot understand this type")
                sendResponse(serverSocket, "ERR", "Cannot understand this type")


    def processLogin(self, clientAddress, username, password):
        print(f"[recv] AUTH from {username}")

        if (
            username in credentials 
            and credentials[username] == password 
            and (username not in activePeers)
        ):
            self.username = username
            print(f"[Send] OK to {username}")
            
            activePeers[username] = {
                "last_activity": time.time(),
                "port": clientAddress[1],
                "heartbeatTimer": None  
            }

            # self.startHeartbeatTimer(username)
            sendResponse(serverSocket, "OK", "Welcome to BitTrickle!\nAvailable commands are: get, lap, lpf, pub, sch", clientAddress)
        else:
            print(f"[Send] ERR to {username}")
            sendResponse(serverSocket, "ERR", "Authentication failed. Please try again.", clientAddress)

    def processHeartbeat(self, username):
        """Reset the heartbeat timer upon receiving a heartbeat."""
        if activePeers[username]["heartbeatTimer"]:
            activePeers[username]["heartbeatTimer"].cancel()
        self.startHeartbeatTimer(username)
        # Update activity time
        if username in activePeers:
            activePeers[username]["last_activity"] = time.time()

    def startHeartbeatTimer(self, username):
        """Starts a timer that will mark the client inactive if a heartbeat isn't received."""
        self.heartbeatTimer = Timer(3, self.markInactive, [username])
        self.heartbeatTimer.start()
        activePeers[username]["heartbeatTimer"] = self.heartbeatTimer

    def markInactive(self, username):
        """Marks the client as inactive if the heartbeat expires."""
        print(f"[Inactive] Client {username} marked inactive due to missed heartbeat.")
        if username in activePeers:
            del activePeers[username]  # Remove the peer from active peers


    def processGetFile(self, filename, username, clientAddress):
        """Checks if any peers have published the requested file."""
        if filename in publishedFiles:
            # Get the list of peers who have published this file
            peersWithFile = list(publishedFiles[filename])

            peerInfo = peersWithFile[0]
            peerName, peerPort = peerInfo
            responseData = {
                "peer_name": peerName,
                "peer_port": peerPort,
                "filename": filename
            }
            sendResponse(serverSocket, "OK", responseData, clientAddress)
            print(f"[Send] OK to {username}")
        else:
            sendResponse(serverSocket, "ERR", "No active peers with the requested file available.", clientAddress)


    def processLap(self, username, clientAddress):
        """Sends a list of active peers to the client."""
        if username in activePeers:
            activeList = [peer for peer in activePeers if peer != username]
            if activeList:
                sendResponse(serverSocket, "OK", "Active Peers: " + ", ".join(activeList), clientAddress)
            else:
                sendResponse(serverSocket, "OK", "No active peers", clientAddress)
            print(f"[Send] OK to {username}")
        else:
            print(f"[Send] ERR to {username}")
            sendResponse(serverSocket, "ERR", "Invalid Username", clientAddress)


    def listPublishedFiles(self, username, clientAddress):
        """Handles the 'lpf' command by sending a list of files published by the user."""
        userFiles = [filename for filename, users in publishedFiles.items() if any(user[0] == username for user in users)]
        
        if userFiles:
            sendResponse(serverSocket, "OK", "Published files:\n" + "\n".join(userFiles), clientAddress)
        else:
            sendResponse(serverSocket, "OK", "You have no published files.", clientAddress)
        
        print(f"[Send] OK to {username}")


    def processSearchFiles(self, substring, username, clientAddress):
        """Handles the 'sch' command to search for files containing the specified substring."""
        matchingFiles = [
            filename for filename, users in publishedFiles.items()
            if substring in filename and any(user_info[0] != username for user_info in users)
        ]
        if matchingFiles:
            sendResponse(serverSocket, "OK", "Files containing substring:\n" + "\n".join(matchingFiles), clientAddress)
        else:
            sendResponse(serverSocket, "OK", "No files with the specified substring found.", clientAddress)
        
        print(f"[Send] SCH results to {username}")


    def registerPeerPort(self, username, port, clientAddress):
        """Registers the peer's dynamically allocated TCP port with the server."""
        if username in credentials:
            activePeers[username]["port"] = port
            print(f"[Register] Registered {username} with IP {clientAddress[0]} and port {port}")
            sendResponse(serverSocket, "OK", "Port registered successfully.", clientAddress)
        else:
            print(f"[Register] ERR: {username} is not authenticated.")
            sendResponse(serverSocket, "ERR", "Username not authenticated.", clientAddress)


    def processPublishFile(self, filename, username, clientAddress):
        """Handles the publishing of a file by a user."""
        if filename not in publishedFiles:
            publishedFiles[filename] = set()

        if username in activePeers:
            peerInfo = activePeers[username]
            publisherInfo = (username, peerInfo["port"])
            publishedFiles[filename].add(publisherInfo)
            print(f"[Register] Added {username} as an owner of {filename}.")
            sendResponse(serverSocket, "OK", "File published successfully.", clientAddress)
        else:
            print(f"[Send] ERR to {username}")
            sendResponse(serverSocket, "ERR", "Please register a port before publishing.", clientAddress)


    def processUnpublishFile(self, filename, username, clientAddress):
        """
        Handles the 'unp' command, which removes the specified file from the list
        of files published by the user if it exists.
        """
        # Check if the file exists and if the user has published it
        if filename in publishedFiles:
            # Filter out the specified user as a publisher of this file
            newPublishers = {publisher for publisher in publishedFiles[filename] if publisher[0] != username}

            if len(newPublishers) < len(publishedFiles[filename]):
                publishedFiles[filename] = newPublishers

                # If no publishers remain, remove the file from the dictionary
                if not newPublishers:
                    del publishedFiles[filename]

                sendResponse(serverSocket, "OK", "File unpublished successfully.", clientAddress)
                print(f"[Send] File '{filename}' unpublished")
            else:
                sendResponse(serverSocket, "OK", "Unpublish failed: You have not published this file.", clientAddress)
                print(f"[Send] Unpublish failed for '{filename}'")
        else:
            sendResponse(serverSocket, "OK", "Unpublish failed: File not found.", clientAddress)
            print(f"'{filename}' not found for unpublish")


    def deleteActivePeer(self, username):
        """Removes the user from active peers."""
        global activePeers
        del activePeers[username]

print("\n===== Server is running =====")
print("===== Waiting for connection request from clients...=====")
    
credentials = loadCredentials('credentials.txt')

clientThread = ClientThread()
clientThread.start()

