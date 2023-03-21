#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time
import os

########################################################################

# Define all of the packet protocol field lengths.

CMD_FIELD_LEN            = 1 # 1 byte commands sent from the client.
FILENAME_SIZE_FIELD_LEN  = 1 # 1 byte file name size field.
FILESIZE_FIELD_LEN       = 8 # 8 byte file size field.
    
# Define a dictionary of commands. The actual command field value must
# be a 1-byte integer. For now, we only define the "GET" command,
# which tells the server to send a file.

CMD = {
    "get"  : b'\x01',
    "put"  : b'\x02',
    "list" : b'\x03'
}

MSG_ENCODING = "utf-8"
SOCKET_TIMEOUT = 4

########################################################################
# recv_bytes frontend to recv
########################################################################

# Call recv to read bytecount_target bytes from the socket. Return a
# status (True or False) and the received butes (in the former case).
def recv_bytes(sock, bytecount_target):
    # Be sure to timeout the socket if we are given the wrong
    # information.
    sock.settimeout(SOCKET_TIMEOUT)
    try:
        byte_recv_count = 0 # total received bytes
        recv_bytes = b''    # complete received message
        while byte_recv_count < bytecount_target:
            # Ask the socket for the remaining byte count.
            new_bytes = sock.recv(bytecount_target-byte_recv_count)
            # If ever the other end closes on us before we are done,
            # give up and return a False status with zero bytes.
            if not new_bytes:
                return(False, b'')
            byte_recv_count += len(new_bytes)
            recv_bytes += new_bytes
        # Turn off the socket timeout if we finish correctly.
        sock.settimeout(None)            
        return (True, recv_bytes)
    # If the socket times out, something went wrong. Return a False
    # status.
    except socket.timeout:
        sock.settimeout(None)        
        print("recv_bytes: Recv socket timeout!")
        return (False, b'')

########################################################################
# SERVER
########################################################################

class Server:

    ALL_IF_ADDRESS = "0.0.0.0"
    SERVICE_SCAN_PORT = 30000
    ADDRESS_PORT = (ALL_IF_ADDRESS, SERVICE_SCAN_PORT)

    MSG_ENCODING = "utf-8"    
    
    SCAN_CMD = "SERVICE DISCOVERY"
    SCAN_CMD_ENCODED = SCAN_CMD.encode(MSG_ENCODING)
    
    MSG = "Mel's File Sharing Service"
    MSG_ENCODED = MSG.encode(MSG_ENCODING)

    RECV_SIZE = 1024
    BACKLOG = 10

    def __init__(self):
        self.create_socket()
        self.receive_forever()

    def create_socket(self):
        try:
            # Create an IPv4 UDP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Get socket layer socket options.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.socket.bind( (Server.ALL_IF_ADDRESS, Server.SERVICE_SCAN_PORT) )
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def receive_forever(self):
        while True:
            try:
                print(Server.MSG, "listening on port {} ...".format(Server.SERVICE_SCAN_PORT))
                recvd_bytes, address = self.socket.recvfrom(Server.RECV_SIZE)

                print("Received: ", recvd_bytes.decode('utf-8'), " Address:", address)
            
                # Decode the received bytes back into strings.
                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)

                # Check if the received packet contains a service scan
                # command.
                if Server.SCAN_CMD in recvd_str:
                    # Send the service advertisement message back to
                    # the client.
                    self.socket.sendto(Server.MSG_ENCODED, address)
            except KeyboardInterrupt:
                print()
                sys.exit(1)

########################################################################
# CLIENT
########################################################################

class Client:

    FILE_DIRECTORY = "client_directory/"

    SCAN_RECV_SIZE = 1024
    MSG_ENCODING = "utf-8"    

    BROADCAST_ADDRESS = "255.255.255.255"
    SERVICE_PORT = 30000
    ADDRESS_PORT = (BROADCAST_ADDRESS, SERVICE_PORT)

    SCAN_CYCLES = 3
    SCAN_TIMEOUT = 2

    SCAN_CMD = "SERVICE DISCOVERY"
    SCAN_CMD_ENCODED = SCAN_CMD.encode(MSG_ENCODING)

    CONNECT_TIMEOUT = 10

    def __init__(self):
        self.get_console_input()

    def get_console_input(self):
        while True:
            self.user_input = input("Use the scan command to find available file sharing services.\nUse the connect <ip address> <port> command to connect once the server is found.\n")

            if (self.user_input == "scan"):
                try:
                    self.connection_scan()
                    self.scan_for_service()
                    continue
                except Exception as msg:
                    print(msg)
                    print("Failed to scan for available servers, please try again.\n")
                    continue
            
            try:
                connect_cmd, self.server_ip_address, self.server_port = self.user_input.split()
            except Exception:
                print("The input is invalid, please try again.\n")
                continue

            if (connect_cmd != "connect"):
                print("The command is invalid, please try again.\n")
                continue

            if (not self.server_port.isdigit()):
                print("The port number is invalid, please try again.\n")
                continue

            try:
                self.connect_to_server()
            except Exception as msg:
                print(msg)
                print("Error connecting to server, please try again.\n")
                continue

            try:
                self.connection_server()
            except (KeyboardInterrupt, EOFError):
                print("Closing server connection ...\n")
                # If we get an error or keyboard interrupt, make sure that we close the socket.
                self.socket.close()

    def connection_scan(self):
        # Service discovery done using UDP packets.
        self.scan_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.scan_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Arrange to send a broadcast service discovery packet.
        self.scan_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # Set the socket for a socket.timeout if a scanning recv
        # fails.
        self.scan_socket.settimeout(Client.SCAN_TIMEOUT);

    def scan_for_service(self):
        # Collect our scan results in a list.
        scan_results = []

        # Repeat the scan procedure a preset number of times.
        for i in range(Client.SCAN_CYCLES):

            # Send a service discovery broadcast.
            print("Sending broadcast scan {}".format(i))            
            self.scan_socket.sendto(Client.SCAN_CMD_ENCODED, Client.ADDRESS_PORT)
        
            while True:
                # Listen for service responses. So long as we keep
                # receiving responses, keep going. Timeout if none are
                # received and terminate the listening for this scan
                # cycle.
                try:
                    recvd_bytes, address = self.scan_socket.recvfrom(Client.SCAN_RECV_SIZE)
                    recvd_msg = recvd_bytes.decode(Client.MSG_ENCODING)

                    # Record only unique services that are found.
                    if (recvd_msg, address) not in scan_results:
                        scan_results.append((recvd_msg, address))
                        continue
                # If we timeout listening for a new response, we are
                # finished.
                except socket.timeout:
                    break

        # Output all of our scan results, if any.
        if scan_results:
            for result in scan_results:
                print(result)
                print()
        else:
            print("No services found.\n")

    def connect_to_server(self):
        # Create an IPv4 TCP socket.
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.socket.settimeout(Client.CONNECT_TIMEOUT)

        # Connect to the server using its socket address tuple.
        self.socket.connect((self.server_ip_address, int(self.server_port)))
        print(f"Connected to {self.server_ip_address} on port {self.server_port}\n")

    def connection_server(self):
        while True:
            self.send_input = input("Input a valid file service command.\n")

            if (self.send_input == "bye"):
                print("Closing server connection ...\n")
                self.socket.close()
                break

            if (self.send_input == "llist"):
                self.llist()
                continue

    def llist(self):
        try:
            if (not os.listdir(Client.FILE_DIRECTORY)): print("The client directory is empty.\n")
            else: print(os.listdir(Client.FILE_DIRECTORY))
        except FileNotFoundError:
            print(Server.FILE_NOT_FOUND_MSG)
            print("Client file directory does not exist!\n")





########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################






