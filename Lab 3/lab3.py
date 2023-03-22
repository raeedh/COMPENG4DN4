#!/usr/bin/env python3

########################################################################

import argparse
import os
import socket
import sys
from threading import Thread

########################################################################

# Define all of the packet protocol field lengths.

CMD_FIELD_LEN = 1  # 1 byte commands sent from the client.
FILENAME_SIZE_FIELD_LEN = 1  # 1 byte file name size field.
FILESIZE_FIELD_LEN = 8  # 8 byte file size field.

# Define a dictionary of commands. The actual command field value must
# be a 1-byte integer.

CMD = {
    "get": 1,
    "put": 2,
    "list": 3
}

MSG_ENCODING = "utf-8"
SOCKET_TIMEOUT = 60


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
        byte_recv_count = 0  # total received bytes
        recv_bytes = b''  # complete received message
        while byte_recv_count < bytecount_target:
            # Ask the socket for the remaining byte count.
            new_bytes = sock.recv(bytecount_target - byte_recv_count)
            # If ever the other end closes on us before we are done,
            # give up and return a False status with zero bytes.
            if not new_bytes:
                return False, b''
            byte_recv_count += len(new_bytes)
            recv_bytes += new_bytes
        # Turn off the socket timeout if we finish correctly.
        sock.settimeout(None)
        return True, recv_bytes
    # If the socket times out, something went wrong. Return a False
    # status.
    except socket.timeout:
        sock.settimeout(None)
        print("recv_bytes: Recv socket timeout!")
        return False, b''


########################################################################
# SERVER
########################################################################

class Server:
    ALL_IF_ADDRESS = "0.0.0.0"
    SERVICE_SCAN_PORT = 30000
    SCAN_ADDRESS_PORT = (ALL_IF_ADDRESS, SERVICE_SCAN_PORT)

    MSG_ENCODING = "utf-8"

    SCAN_CMD = "SERVICE DISCOVERY"
    SCAN_CMD_ENCODED = SCAN_CMD.encode(MSG_ENCODING)

    MSG = "A&R's File Sharing Service Availabe on Port 30001 (connect 172.20.22.157 30001)"
    MSG_ENCODED = MSG.encode(MSG_ENCODING)

    LISTEN_PORT = 30001
    LISTEN_ADDRESS_PORT = (ALL_IF_ADDRESS, LISTEN_PORT)

    RECV_SIZE = 1024
    BACKLOG = 10

    FILE_DIRECTORY = "server_directory/"
    FILE_NOT_FOUND_MSG = "Error: Requested file is not available!\n"

    def __init__(self):
        udp_thread = Thread(target=self.listen_for_udp)
        udp_thread.start()

        self.create_listen_socket()
        self.process_connections_forever()

        udp_thread.join()

    def listen_for_udp(self):
        self.create_udp_socket()
        self.receive_udp_forever()

    def create_udp_socket(self):
        try:
            # Create an IPv4 UDP socket.
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Get socket layer socket options.
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.udp_socket.bind(Server.SCAN_ADDRESS_PORT)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def receive_udp_forever(self):
        while True:
            try:
                print(Server.MSG, "listening on port {} ...".format(Server.SERVICE_SCAN_PORT))
                recvd_bytes, address = self.udp_socket.recvfrom(Server.RECV_SIZE)

                print("Received: ", recvd_bytes.decode('utf-8'), " Address:", address)

                # Decode the received bytes back into strings.
                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)

                # Check if the received packet contains a service scan command.
                if Server.SCAN_CMD in recvd_str:
                    # Send the service advertisement message back to the client.
                    self.udp_socket.sendto(Server.MSG_ENCODED, address)
            except KeyboardInterrupt:
                print()
                sys.exit(1)

    def create_listen_socket(self):
        try:
            # Create the TCP server listen socket in the usual way.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(Server.LISTEN_ADDRESS_PORT)
            self.socket.listen(Server.BACKLOG)
            print("Listening on port {} ...".format(Server.LISTEN_PORT))
        except Exception as msg:
            print(msg)
            exit()

    def process_connections_forever(self):
        try:
            while True:
                self.connection_handler(self.socket.accept())
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()

    def connection_handler(self, client):
        connection, address = client
        print("Connection received from {}.".format(address))

        ################################################################
        # Process a connection and see if the client wants a file that we have.

        # Read the command and see if it is a GET command.
        status, cmd_field = recv_bytes(connection, CMD_FIELD_LEN)
        # If the read fails, give up.
        if not status:
            print("Closing connection ...")
            connection.close()
            return
        # Convert the command to our native byte order.
        cmd = int.from_bytes(cmd_field, byteorder='big')
        # Give up if we don't get a GET command.
        if cmd == CMD["get"]:
            self.get_file(connection)
        elif cmd == CMD["put"]:
            self.put_file(connection)
        elif cmd == CMD["list"]:
            self.list(connection)
        else:
            print("Valid command not received. Closing connection ...")
            connection.close()
            return

    def get_file(self, connection):
        # GET command is good. Read the filename size (bytes).
        status, filename_size_field = recv_bytes(connection, FILENAME_SIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")
            connection.close()
            return

        filename_size_bytes = int.from_bytes(filename_size_field, byteorder='big')
        if not filename_size_bytes:
            print("Connection is closed!")
            connection.close()
            return

        print('Filename size (bytes) = ', filename_size_bytes)

        # Now read and decode the requested filename.
        status, filename_bytes = recv_bytes(connection, filename_size_bytes)
        if not status:
            print("Closing connection ...")
            connection.close()
            return
        if not filename_bytes:
            print("Connection is closed!")
            connection.close()
            return

        filename = filename_bytes.decode(MSG_ENCODING)
        print('Requested filename = ', filename)

        ################################################################
        # See if we can open the requested file. If so, send it.

        # If we can't find the requested file, shutdown the connection and wait for someone else.
        try:
            file = open(Server.FILE_DIRECTORY + filename, 'r').read()
        except FileNotFoundError:
            print(Server.FILE_NOT_FOUND_MSG)
            connection.close()
            return

        # Encode the file contents into bytes, record its size and generate the file size field used for transmission.
        file_bytes = file.encode(MSG_ENCODING)
        file_size_bytes = len(file_bytes)
        file_size_field = file_size_bytes.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

        # Create the packet to be sent with the header field.
        pkt = file_size_field + file_bytes

        try:
            # Send the packet to the connected client.
            connection.sendall(pkt)
            print("Sending file: ", filename)
            print("file size field: ", file_size_field.hex(), "\n")
            # time.sleep(20)
        except socket.error:
            # If the client has closed the connection, close the socket on this end.
            print("Closing client connection ...")
            connection.close()
            return

    def put_file(self, connection):
        # PUT command is good. Read the filename size (bytes).
        status, filename_size_field = recv_bytes(connection, FILENAME_SIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")
            connection.close()
            return

        filename_size_bytes = int.from_bytes(filename_size_field, byteorder='big')
        if not filename_size_bytes:
            print("Connection is closed!")
            connection.close()
            return

        print('Filename size (bytes) = ', filename_size_bytes)

        # Now read and decode the requested filename.
        status, filename_bytes = recv_bytes(connection, filename_size_bytes)
        if not status:
            print("Closing connection ...")
            connection.close()
            return
        if not filename_bytes:
            print("Connection is closed!")
            connection.close()
            return

        filename = filename_bytes.decode(MSG_ENCODING)
        print('Requested filename = ', filename)

        ################################################################
        # Process the file transfer response from the client

        # Read the file size field returned by the server.
        status, file_size_bytes = recv_bytes(connection, FILESIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")
            connection.close()
            return

        print("File size bytes = ", file_size_bytes.hex())
        if len(file_size_bytes) == 0:
            connection.close()
            return

        # Make sure that you interpret it in host byte order.
        file_size = int.from_bytes(file_size_bytes, byteorder='big')
        print("File size = ", file_size)

        status, recvd_bytes_total = recv_bytes(connection, file_size)
        if not status:
            print("Closing connection ...")
            connection.close()
            return

        # Receive the file itself.
        try:
            # Create a file using the received filename and store the data.
            print(f"Received {len(recvd_bytes_total)} bytes. Creating file: {filename}")
            recvd_file = recvd_bytes_total.decode(MSG_ENCODING)

            with open(filename, 'w') as f:
                f.write(recvd_file)
        except KeyboardInterrupt:
            print()
            exit(1)

    def list(self, connection):
        num_files = 0

        try:
            if not os.listdir(Server.FILE_DIRECTORY):
                print("The client directory is empty.\n")
                file_size_field = num_files.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')
                connection.sendall(file_size_field)
            else:
                files = "\n".join(os.listdir(Server.FILE_DIRECTORY)).encode(MSG_ENCODING)
                file_size_field = len(files).to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

                pkt = file_size_field + files
                connection.sendall(pkt)
        except FileNotFoundError:
            print(Server.FILE_NOT_FOUND_MSG)
            print("Client file directory does not exist!\n")
            file_size_field = num_files.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')
            connection.sendall(file_size_field)


########################################################################
# CLIENT
########################################################################

class Client:
    FILE_DIRECTORY = "client_directory/"
    FILE_NOT_FOUND_MSG = "Error: Requested file is not available!\n"

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
            self.user_input = input("Use the scan command to find available file sharing services.\nUse the connect <ip address> <port> "
                                    "command to connect once the server is found.\n")

            if self.user_input == "scan":
                try:
                    self.connection_scan()
                    self.scan_for_service()
                    continue
                except Exception as msg:
                    print(msg)
                    print("Failed to scan for available servers, please try again.\n")
                    continue

            if self.user_input == "llist":
                try:
                    self.llist()
                    continue
                except Exception as msg:
                    print(msg)
                    print("Failed to scan local directory, please try again.\n")
                    continue

            try:
                connect_cmd, self.server_ip_address, self.server_port = self.user_input.split()
            except Exception:
                print("The input is invalid, please try again.\n")
                continue

            if connect_cmd != "connect":
                print("The command is invalid, please try again.\n")
                continue

            if not self.server_port.isdigit():
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
        self.scan_socket.settimeout(Client.SCAN_TIMEOUT)

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

            if self.send_input == "bye":
                print("Closing server connection ...\n")
                self.socket.close()
                break

            if self.send_input == "llist":
                try:
                    self.llist()
                    continue
                except Exception as msg:
                    print(msg)
                    print("Error getting local file list, please try again.\n")
                    continue

            if self.send_input == "rlist":
                try:
                    self.rlist()
                    continue
                except Exception as msg:
                    print(msg)
                    print("Error getting remote file list from server, please try again.\n")
                    continue

            try:
                connection_cmd, self.filename, = self.send_input.split()
            except Exception:
                print("The input is invalid, please try again.\n")
                continue

            if connection_cmd == "get":
                try:
                    self.get_file()
                except Exception as msg:
                    print(msg)
                    print("Error getting file from server, please try again.\n")
                    continue

            if connection_cmd == "put":
                if not os.path.isfile(Client.FILE_DIRECTORY + self.filename):
                    print(Client.FILE_NOT_FOUND_MSG)
                    continue

                try:
                    self.put_file()
                except Exception as msg:
                    print(msg)
                    print("Error putting file on server, please try again.\n")
                    continue

    def llist(self):
        try:
            if not os.listdir(Client.FILE_DIRECTORY):
                print("The client directory is empty.\n")
            else:
                print(os.listdir(Client.FILE_DIRECTORY))
        except FileNotFoundError:
            print(Client.FILE_NOT_FOUND_MSG)
            print("Client file directory does not exist!\n")

    def rlist(self):
        # Create the packet cmd field.
        cmd_field = CMD["list"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        # Send the request packet to the server.
        self.socket.sendall(cmd_field)

        ################################################################
        # Process the list repsonse from the server

        # Read the response size returned by the server.
        status, response_size_bytes = recv_bytes(self.socket, FILESIZE_FIELD_LEN)
        if not status:
            print("No listing size returned by server...\n")
            return

        print("Response size bytes = ", response_size_bytes.hex())
        if len(response_size_bytes) == 0:
            return

        # Make sure that you interpret it in host byte order.
        listing_size = int.from_bytes(response_size_bytes, byteorder='big')
        print("Listing size = ", listing_size)

        status, recvd_bytes_total = recv_bytes(self.socket, listing_size)
        if not status:
            print("No listing returned by server...\n")
            return
        try:
            print(recvd_bytes_total.decode(MSG_ENCODING))
        except KeyboardInterrupt:
            print()

    def get_file(self):
        ################################################################
        # Generate a file transfer request to the server

        # Create the packet cmd field.
        cmd_field = CMD["get"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        # Create the packet filename field.
        filename_field_bytes = self.filename.encode(MSG_ENCODING)

        # Create the packet filename size field.
        filename_size_field = len(filename_field_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')

        # Create the packet.
        print("CMD field: ", cmd_field.hex())
        print("Filename_size_field: ", filename_size_field.hex())
        print("Filename field: ", filename_field_bytes.hex())

        pkt = cmd_field + filename_size_field + filename_field_bytes

        # Send the request packet to the server.
        self.socket.sendall(pkt)

        ################################################################
        # Process the file transfer repsonse from the server

        # Read the file size field returned by the server.
        status, file_size_bytes = recv_bytes(self.socket, FILESIZE_FIELD_LEN)
        if not status:
            print("No file size returned by server...\n")
            return

        print("File size bytes = ", file_size_bytes.hex())
        if len(file_size_bytes) == 0:
            return

        # Make sure that you interpret it in host byte order.
        file_size = int.from_bytes(file_size_bytes, byteorder='big')
        print("File size = ", file_size)

        # self.socket.settimeout(4)                                  
        status, recvd_bytes_total = recv_bytes(self.socket, file_size)
        if not status:
            print("No file returned by server...\n")
            return
        # print("recvd_bytes_total = ", recvd_bytes_total)
        # Receive the file itself.
        try:
            # Create a file using the received filename and store the
            # data.
            print("Received {} bytes. Creating file: {}" \
                  .format(len(recvd_bytes_total), self.filename))

            with open(Client.FILE_DIRECTORY + self.filename, 'w') as f:
                recvd_file = recvd_bytes_total.decode(MSG_ENCODING)
                f.write(recvd_file)
            print(recvd_file)
        except KeyboardInterrupt:
            print()

    def put_file(self):
        ################################################################
        # Generate a file transfer request to the server

        # Create the packet cmd field.
        cmd_field = CMD["put"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        # Create the packet filename field.
        filename_field_bytes = self.filename.encode(MSG_ENCODING)

        # Create the packet filename size field.
        filename_size_field = len(filename_field_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')

        # Create the packet.
        print("CMD field: ", cmd_field.hex())
        print("Filename_size_field: ", filename_size_field.hex())
        print("Filename field: ", filename_field_bytes.hex())

        ################################################################
        # See if we can open the requested file. If so, send it.

        # If we can't find the requested file, exit function
        try:
            file = open(Client.FILE_DIRECTORY + self.filename, 'r').read()
        except FileNotFoundError:
            print(Client.FILE_NOT_FOUND_MSG)
            return

        # Encode the file contents into bytes, record its size and
        # generate the file size field used for transmission.
        file_bytes = file.encode(MSG_ENCODING)
        file_size_bytes = len(file_bytes)
        file_size_field = file_size_bytes.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

        # Create the packet to be sent with the header field.
        pkt = cmd_field + filename_field_bytes + filename_size_field + file_size_field + file_bytes

        try:
            # Send the packet to the connected server.
            self.socket.sendall(pkt)
            print("Sending file: ", self.filename)
            print("file size field: ", file_size_field.hex(), "\n")
            # time.sleep(20)
        except socket.error:
            print("Error occuring sending file to server...\n")
            return
        finally:
            return


########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'client': Client, 'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles,
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################
