#!/usr/bin/env python3

########################################################################

import argparse
import os
import socket
import sys
from threading import Thread
import ipaddress
import select
import fcntl
import os

########################################################################

CRDS_PORT = 50001
CRDS_ADDRESS = "0.0.0.0"
CRDS_ADRESS_PORT = (CRDS_ADDRESS, CRDS_PORT)

MULTICAST_ADDRESS = "239.0.0.10"
MULTICAST_PORT    =  2000

# Make them into a tuple.
MULTICAST_ADDRESS_PORT = (MULTICAST_ADDRESS, MULTICAST_PORT)

# Ethernet/Wi-Fi interface address
IFACE_ADDRESS = "0.0.0.0"
RX_IFACE_ADDRESS = "0.0.0.0"
RX_BIND_ADDRESS = "0.0.0.0"
RX_BIND_ADDRESS_PORT = (RX_BIND_ADDRESS, MULTICAST_PORT)

########################################################################

# Define all of the packet protocol field lengths.

CMD_FIELD_LEN = 1  # 1 byte commands sent from the client.
FILENAME_SIZE_FIELD_LEN = 1  # 1 byte file name size field.
FILESIZE_FIELD_LEN = 8  # 8 byte file size field.

# Define a dictionary of commands. The actual command field value must
# be a 1-byte integer.

CMD = {
    "getdir": 1,
    "makeroom": 2,
    "deleteroom": 3,
    "chat": 4
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

    MSG = "A&R's File Sharing Service Availabe on Port 30001 (connect 0.0.0.0 30001)"
    MSG_ENCODED = MSG.encode(MSG_ENCODING)

    LISTEN_PORT = 30001
    LISTEN_ADDRESS_PORT = (ALL_IF_ADDRESS, LISTEN_PORT)

    RECV_SIZE = 1024
    BACKLOG = 10

    FILE_DIRECTORY = "server_directory/"
    FILE_NOT_FOUND_MSG = "Error: Requested file is not available!\n"

    def __init__(self):
        print(os.listdir(Server.FILE_DIRECTORY)) 

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
                print(Server.MSG, "Listening for service discovery messages on SDP port {}.".format(Server.SERVICE_SCAN_PORT))
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
        except Exception as msg:
            print(msg)
            exit()

    def process_connections_forever(self):
        try:
            while True:
                print("Listening for file sharing connections on port {}.".format(Server.LISTEN_ADDRESS_PORT))
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
        try:
            while True:
                # Read the command and see if it is a GET command.
                status, cmd_field = recv_bytes(connection, CMD_FIELD_LEN)
                # If the read fails, give up.
                if not status:
                    print("Closing connection ...")
                    connection.close()
                    return
                # Convert the command to our native byte order.
                cmd = int.from_bytes(cmd_field, byteorder='big')

                # Give up if we don't get a valid command.
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
        except KeyboardInterrupt:
            print()

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
            file = open(Server.FILE_DIRECTORY + filename, 'rb').read()
        except FileNotFoundError:
            print(Server.FILE_NOT_FOUND_MSG)
            connection.close()
            return

        # Encode the file contents into bytes, record its size and generate the file size field used for transmission.
        file_size_bytes = len(file)
        file_size_field = file_size_bytes.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

        # Create the packet to be sent with the header field.
        pkt = file_size_field + file

        try:
            # Send the packet to the connected client.
            connection.sendall(pkt)
            print("Sending file: ", filename)
            print("file size field: ", file_size_field.hex(), "\n")
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

            with open(Server.FILE_DIRECTORY + filename, 'wb') as f:
                f.write(recvd_bytes_total)
        except KeyboardInterrupt:
            print()
            exit(1)

    def list(self, connection):
        num_files = 0

        try:
            if not os.listdir(Server.FILE_DIRECTORY):
                print("The server directory is empty.\n")
                file_size_field = num_files.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')
                connection.sendall(file_size_field)
            else:
                files = "\n".join(os.listdir(Server.FILE_DIRECTORY)).encode(MSG_ENCODING)
                file_size_field = len(files).to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

                pkt = file_size_field + files
                connection.sendall(pkt)
        except FileNotFoundError:
            print(Server.FILE_NOT_FOUND_MSG)
            print("Server file directory does not exist!\n")
            file_size_field = num_files.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')
            connection.sendall(file_size_field)


########################################################################
# CLIENT
########################################################################
class Client:
    CONNECT_TIMEOUT = 10
    RECV_SIZE = 256

    def __init__(self):
        # Default chat name: user
        self.chat_name = "user: "

        self.get_console_input()

    def get_console_input(self):
        while True:
            self.user_input = input("Use the connect command to issue CRDS commands, or enter a chat.\n")

            if self.user_input == "connect":
                try:
                    self.connect_to_server()
                except Exception as msg:
                    print(msg)
                    print("Connection to CRDS failed, please try again.\n")
                    continue

                try:
                    self.connection_server()
                except (KeyboardInterrupt, EOFError):
                    print("Closing server connection...\n")
                    # If we get an error or keyboard interrupt, make sure that we close the socket.
                    self.socket.close()
                    continue

            try:
                chat_cmd, name = self.user_input.split()
            except Exception:
                print("The input is invalid, please try again.\n")
                continue

            if chat_cmd == "name":
                self.chat_name = name + ": "
            elif chat_cmd == "chat":
                try:
                    self.chatroom(name)
                except (KeyboardInterrupt, EOFError):
                    print("Closing chat connection...\n")
                    continue

    def connect_to_server(self):
        # Create an IPv4 TCP socket.
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.socket.settimeout(Client.CONNECT_TIMEOUT)

        # Connect to the server using its socket address tuple.
        self.socket.connect(CRDS_ADRESS_PORT)
        print(f"Connected to {CRDS_ADDRESS} on port {CRDS_PORT}\n")

    def connection_server(self):
        while True:
            self.crds_input = input("Input a valid CRDS command.\n")

            if self.crds_input == "bye":
                print("Closing server connection ...\n")
                self.socket.close()
                break
            elif self.crds_input == "getdir":
                try:
                    self.getdir()
                except Exception as msg:
                    print(msg)
                    print("Error excuting CRDS command, closing server connection.\n")
                    self.socket.close()
                    break
            
            try:
                crds_cmd, chat_room_name, chat_room_address, chat_room_port = self.crds_input.split()
            except Exception:
                print("The input is invalid, please try again.\n")
                continue
            
            if crds_cmd == "makeroom":
                if (ipaddress.ip_address(chat_room_address) in ipaddress.ip_network('239.0.0.0/8')) and (chat_room_port.isdigit()):
                    try:
                        self.makeroom(chat_room_name, chat_room_address, chat_room_port)
                        continue
                    except Exception as msg:
                        print(msg)
                        print("Error making room, closing server connection.\n")
                        self.socket.close()
                        break
            
            try:
                crds_cmd, chat_room_name = self.crds_input.split()
            except Exception:
                print("The input is invalid, please try again.\n")
                continue

            if crds_cmd == "deleteroom":
                try:
                    self.deleteroom(chat_room_name)
                    continue
                except Exception as msg:
                        print(msg)
                        print("Error deleting room, closing server connection.\n")
                        self.socket.close()
                        break


            print("Invalid command, please try again.\n")

    def getdir(self):
        # Create the packet cmd field.
        cmd_field = CMD["getdir"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        # Send the request packet to the server.
        self.socket.sendall(cmd_field)

        ################################################################
        # Process the list response from the server

        # Read the response size returned by the server.
        status, response_size_bytes = recv_bytes(self.socket, FILESIZE_FIELD_LEN)
        if not status:
            # print("No response from server...\n")
            raise Exception

        # print("Response size bytes = ", response_size_bytes.hex())
        if len(response_size_bytes) == 0:
            return

        # Make sure that you interpret it in host byte order.
        listing_size = int.from_bytes(response_size_bytes, byteorder='big')
        # print("Listing size = ", listing_size)

        status, recvd_bytes_total = recv_bytes(self.socket, listing_size)
        if not status:
            print("No response from server...\n")
            raise Exception
        try:
            print(recvd_bytes_total.decode(MSG_ENCODING))
        except KeyboardInterrupt:
            print()

    def makeroom(self, chat_room_name, chat_room_address, chat_room_port):
        # Create the packet cmd field.
        cmd_field = CMD["makeroom"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        chat_room_name_bytes = chat_room_name.encode(MSG_ENCODING)
        chat_room_address_bytes = chat_room_address.encode(MSG_ENCODING)
        chat_room_port_bytes = chat_room_port.encode(MSG_ENCODING)

        chat_room_name_size_field = len(chat_room_name_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')
        chat_room_address_size_field = len(chat_room_address_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')
        chat_room_port_size_field = len(chat_room_port_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')

        pkt = cmd_field \
            + chat_room_name_size_field + chat_room_name_bytes \
            + chat_room_address_size_field + chat_room_address_bytes \
            + chat_room_port_size_field + chat_room_port_bytes

        # Send the request packet to the server.
        self.socket.sendall(pkt)

    def deleteroom(self, chat_room_name):
        # Create the packet cmd field.
        cmd_field = CMD["deleteroom"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        chat_room_name_bytes = chat_room_name.encode(MSG_ENCODING)

        chat_room_name_size_field = len(chat_room_name_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')

        pkt = cmd_field \
            + chat_room_name_size_field + chat_room_name_bytes

        # Send the request packet to the server.
        self.socket.sendall(pkt)

    def getchat(self, chat_room_name):
        # Create the packet cmd field.
        cmd_field = CMD["chat"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        chat_room_name_bytes = chat_room_name.encode(MSG_ENCODING)

        chat_room_name_size_field = len(chat_room_name_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')

        pkt = cmd_field \
            + chat_room_name_size_field + chat_room_name_bytes

        # Send the request packet to the server.
        self.socket.sendall(pkt)

        ################################################################
        # Process the chat room response from the server

        # Read the chat room address size field returned by the server.
        status, chat_room_address_size_field = recv_bytes(self.socket, FILENAME_SIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...\n")
            self.socket.close()
            return

        chat_room_address_size_bytes = int.from_bytes(chat_room_address_size_field, byteorder='big')
        if not chat_room_address_size_bytes:
            print("Connection is closed!\n")
            self.socket.close()
            return

        # Now read and decode the requested chat room address.
        status, chat_room_address_bytes = recv_bytes(self.socket, chat_room_address_size_bytes)
        if not status:
            print("Closing connection ...")
            self.socket.close()
            return
        if not chat_room_address_bytes:
            print("Connection is closed!")
            self.socket.close()
            return

        chat_room_address = chat_room_address_bytes.decode(MSG_ENCODING)

        # Read the chat room port size field returned by the server.
        status, chat_room_port_size_field = recv_bytes(self.socket, FILENAME_SIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...\n")
            self.socket.close()
            return

        chat_room_port_size_bytes = int.from_bytes(chat_room_port_size_field, byteorder='big')
        if not chat_room_port_size_bytes:
            print("Connection is closed!\n")
            self.socket.close()
            return

        # Now read and decode the requested chat room address.
        status, chat_room_port_bytes = recv_bytes(self.socket, chat_room_port_size_bytes)
        if not status:
            print("Closing connection ...")
            self.socket.close()
            return
        if not chat_room_port_bytes:
            print("Connection is closed!")
            self.socket.close()
            return

        chat_room_port = chat_room_port_bytes.decode(MSG_ENCODING)

        self.chat_address = chat_room_address
        self.chat_port = chat_room_port

    def chatroom(self, name):
        try:
            self.connect_to_server()
        except Exception as msg:
            print(msg)
            print("Unable to retrieve multicast address/port for the associated chat room, please try again.\n")
            return

        try:
            self.getchat(name)
        except Exception as msg:
            print(msg)
            print("Unable to retrieve multicast address/port for the associated chat room, please try again.\n")
            self.socket.close()
            return

        try:
            self.get_socket()
        except Exception as msg:
            print(msg)
            print("Error connecting to chat room, please try again.")
            return
        try:
            self.receive_forever()
        except Exception as msg:
            print(msg)
            print("Error connecting to chat room, please try again.")
            self.chat_socket.close()
            return

    def get_socket(self):
        self.chat_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.chat_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        
        self.chat_socket.bind((RX_BIND_ADDRESS, self.chat_port))

        multicast_group_bytes = socket.inet_aton(self.chat_address)
        # print("Multicast Group: ", MULTICAST_ADDRESS)

        # Set up the interface to be used.
        multicast_iface_bytes = socket.inet_aton(RX_IFACE_ADDRESS)

        # Form the multicast request.
        multicast_request = multicast_group_bytes + multicast_iface_bytes
        # print("multicast_request = ", multicast_request)

        # Issue the Multicast IP Add Membership request.
        # print("Adding membership (address/interface): ", MULTICAST_ADDRESS,"/", RX_IFACE_ADDRESS)
        self.chat_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)

    def receive_forever(self):
        # Set stdin to non-blocking mode
        fd = sys.stdin.fileno()
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        while True:
            sockets_list = [sys.stdin, self.chat_socket]
            read_ready, write_ready, except_ready = select.select(sockets_list, [], [])

            for socket in read_ready:
                if socket == self.chat_socket:
                    try:
                        message, address = self.chat_socket.recvfrom(Client.RECV_SIZE)
                    except:
                        # If no message is received, move on to next iteration of loop
                        continue
                    if not message:
                        # If server has closed the connection, exit loop
                        return
                    print(message.decode())
            else:
                # Send message to chat room
                message = sys.stdin.readline()
                if message:
                    self.chat_socket.sendto((self.chat_name + message).encode(), (self.chat_address, self.chat_port))
                    # sys.stdout.write(self.chat_name + message)
                    # sys.stdout.flush()

                    # Check for exit command
                    if message.strip() == 'exit':
                        return
            # try:
            #     data, address_port = self.chat_socket.recvfrom(Client.RECV_SIZE)
            #     address, port = address_port
            #     print("Received: {} {}".format(data.decode('utf-8'), address_port))
            # except KeyboardInterrupt:
            #     print(); exit()
            # except Exception as msg:
            #     print(msg)
            #     sys.exit(1)

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
