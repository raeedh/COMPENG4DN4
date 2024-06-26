#!/usr/bin/env python3

########################################################################

import argparse
import fcntl
import ipaddress
import os
import socket
import sys

import select

########################################################################

CRDS_PORT = 50001
CRDS_ADDRESS = "0.0.0.0"
CRDS_ADRESS_PORT = (CRDS_ADDRESS, CRDS_PORT)

# Ethernet/Wi-Fi interface address
IFACE_ADDRESS = "0.0.0.0"
RX_IFACE_ADDRESS = "0.0.0.0"
RX_BIND_ADDRESS = "0.0.0.0"

# Create a 1-byte maximum hop count byte used in the multicast
# packets (i.e., TTL, time-to-live).
TTL = 1  # Hops
TTL_BYTE = TTL.to_bytes(1, byteorder='big')

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
    RECV_SIZE = 1024
    BACKLOG = 10

    def __init__(self):
        self.chat_rooms = {}

        self.create_listen_socket()
        self.initialize_select_lists()

        self.process_connections_forever_select()

    def create_listen_socket(self):
        try:
            # Create the TCP server listen socket in the usual way.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(CRDS_ADRESS_PORT)
            self.socket.listen(Server.BACKLOG)

            print("Chat Room Directory Server listening on port {}.".format(CRDS_ADRESS_PORT))
        except Exception as msg:
            print(msg)
            exit()

    def initialize_select_lists(self):
        self.read_list = [self.socket]

    def process_connections_forever_select(self):
        try:
            while True:
                self.read_ready, self.write_ready, self.except_ready = select.select(
                    self.read_list, [], [])

                self.process_read_sockets()
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()

    def process_read_sockets(self):
        # Iterate through the read ready sockets, processing each one
        # in turn.
        for read_socket in self.read_ready:
            if read_socket is self.socket:
                client, address = read_socket.accept()
                print("-" * 72)
                print("Connection received from {}.".format(address))
                client.setblocking(False)
                self.read_list.append(client)
            else:
                status, cmd_field = recv_bytes(read_socket, CMD_FIELD_LEN)

                if status:
                    cmd = int.from_bytes(cmd_field, byteorder='big')

                    # Give up if we don't get a valid command.
                    if cmd == CMD["getdir"]:
                        self.getdir(read_socket)
                    elif cmd == CMD["makeroom"]:
                        self.makeroom(read_socket)
                    elif cmd == CMD["deleteroom"]:
                        self.deleteroom(read_socket)
                    elif cmd == CMD["chat"]:
                        self.chat(read_socket)
                        self.read_list.remove(read_socket)
                        read_socket.close()
                    else:
                        print("Valid command not received. Closing connection ...")
                        self.read_list.remove(read_socket)
                        read_socket.close()
                else:
                    print("Closing client connection ...")
                    self.read_list.remove(read_socket)
                    read_socket.close()

    def deleteroom(self, connection):
        print("deleteroom command received!")
        # deleteroom command is good. Read the chat room name size (bytes).
        status, chat_room_name_size_field = recv_bytes(connection, FILENAME_SIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")
            connection.close()
            return

        chat_room_name_size_bytes = int.from_bytes(chat_room_name_size_field, byteorder='big')
        if not chat_room_name_size_bytes:
            print("Connection is closed!")
            connection.close()
            return

        # Now read and decode the requested chat room name.
        status, chat_room_name_bytes = recv_bytes(connection, chat_room_name_size_bytes)
        if not status:
            print("Closing connection ...")
            connection.close()
            return
        if not chat_room_name_bytes:
            print("Connection is closed!")
            connection.close()
            return

        chat_room_name = chat_room_name_bytes.decode(MSG_ENCODING)
        print('Requested chat name = ', chat_room_name)

        try:
            self.chat_rooms.pop(chat_room_name)
        except:
            print("Chat room does not exist!\n")
            return

    def makeroom(self, connection):
        print("makeroom command received!")
        # makeroom command is good. Read the chat room name size (bytes).
        status, chat_room_name_size_field = recv_bytes(connection, FILENAME_SIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")
            connection.close()
            return

        chat_room_name_size_bytes = int.from_bytes(chat_room_name_size_field, byteorder='big')
        if not chat_room_name_size_bytes:
            print("Connection is closed!")
            connection.close()
            return

        # Now read and decode the requested chat room name.
        status, chat_room_name_bytes = recv_bytes(connection, chat_room_name_size_bytes)
        if not status:
            print("Closing connection ...")
            connection.close()
            return
        if not chat_room_name_bytes:
            print("Connection is closed!")
            connection.close()
            return

        chat_room_name = chat_room_name_bytes.decode(MSG_ENCODING)
        print('Requested chat name = ', chat_room_name)

        # chat room address
        status, chat_room_address_size_field = recv_bytes(connection, FILENAME_SIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")
            connection.close()
            return

        chat_room_address_size_bytes = int.from_bytes(chat_room_address_size_field, byteorder='big')
        if not chat_room_address_size_bytes:
            print("Connection is closed!")
            connection.close()
            return

        # Now read and decode the requested chat room address.
        status, chat_room_address_bytes = recv_bytes(connection, chat_room_address_size_bytes)
        if not status:
            print("Closing connection ...")
            connection.close()
            return
        if not chat_room_address_bytes:
            print("Connection is closed!")
            connection.close()
            return

        chat_room_address = chat_room_address_bytes.decode(MSG_ENCODING)
        print('Requested chat address = ', chat_room_address)

        # chat room port
        status, chat_room_port_size_field = recv_bytes(connection, FILENAME_SIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")
            connection.close()
            return

        chat_room_port_size_bytes = int.from_bytes(chat_room_port_size_field, byteorder='big')
        if not chat_room_port_size_bytes:
            print("Connection is closed!")
            connection.close()
            return

        # Now read and decode the requested chat room address.
        status, chat_room_port_bytes = recv_bytes(connection, chat_room_port_size_bytes)
        if not status:
            print("Closing connection ...")
            connection.close()
            return
        if not chat_room_port_bytes:
            print("Connection is closed!")
            connection.close()
            return

        chat_room_port = int(chat_room_port_bytes.decode(MSG_ENCODING))
        print('Requested chat port = ', chat_room_port, '\n')

        self.chat_rooms[chat_room_name] = (chat_room_address, chat_room_port)

    def getdir(self, connection):
        print("The getdir command was received.")

        num_chats = 0

        room_info_str = ""
        for name, (address, port) in self.chat_rooms.items():
            room_info_str += f"{name}: {address}:{port}\n"

        if not room_info_str:
            print("The chat directory is empty.\n")
            response_size = num_chats.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')
            connection.sendall(response_size)
        else:
            response_size = len(room_info_str).to_bytes(FILESIZE_FIELD_LEN, byteorder='big')
            response = room_info_str.encode(MSG_ENCODING)

            pkt = response_size + response
            connection.sendall(pkt)

    def chat(self, connection):
        print("The chat command was received.")

        status, chat_room_name_size_field = recv_bytes(connection, FILENAME_SIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")
            connection.close()
            return

        chat_room_name_size_bytes = int.from_bytes(chat_room_name_size_field, byteorder='big')
        if not chat_room_name_size_bytes:
            print("Connection is closed!")
            connection.close()
            return

        # Now read and decode the requested chat room name.
        status, chat_room_name_bytes = recv_bytes(connection, chat_room_name_size_bytes)
        if not status:
            print("Closing connection ...")
            connection.close()
            return
        if not chat_room_name_bytes:
            print("Connection is closed!")
            connection.close()
            return

        chat_room_name = chat_room_name_bytes.decode(MSG_ENCODING)
        print('Requested chat name = ', chat_room_name)

        chat_does_not_exist = 0

        try:
            address, port = self.chat_rooms[chat_room_name]
        except:
            print("The chat room does not exist!\n")
            response_size = chat_does_not_exist.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')
            connection.sendall(response_size)
            return

        chat_room_address_bytes = address.encode(MSG_ENCODING)
        chat_room_port_bytes = str(port).encode(MSG_ENCODING)

        chat_room_address_size_field = len(chat_room_address_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')
        chat_room_port_size_field = len(chat_room_port_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')

        pkt = chat_room_address_size_field + chat_room_address_bytes \
              + chat_room_port_size_field + chat_room_port_bytes

        # Send the request packet to the server.
        connection.sendall(pkt)


########################################################################
# CLIENT
########################################################################
class Client:
    CONNECT_TIMEOUT = 10
    RECV_SIZE = 256

    def __init__(self):
        # Default chat name: user
        self.chat_name = "user: "
        self.chat_address = ""
        self.chat_port = 0

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
                    continue
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
                    continue
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
                    print()
                    continue
                except Exception as msg:
                    print(msg)
                    print("Error excuting CRDS command, closing server connection.\n")
                    self.socket.close()
                    break

            try:
                crds_cmd, chat_room_name, chat_room_address, chat_room_port = self.crds_input.split()

                if crds_cmd == "makeroom":
                    try:
                        if (ipaddress.ip_address(chat_room_address) in ipaddress.ip_network('239.0.0.0/8')) and (chat_room_port.isdigit()):
                            try:
                                self.makeroom(chat_room_name, chat_room_address, chat_room_port)
                                print()
                                continue
                            except Exception as msg:
                                print(msg)
                                print("Error making room, closing server connection.\n")
                                self.socket.close()
                                break
                    except Exception as msg:
                        print(msg)
                        print("The input is invalid, please try again.\n")
                        continue
            except Exception:
                pass

            try:
                crds_cmd, chat_room_name = self.crds_input.split()
            except Exception:
                print("The input is invalid, please try again.\n")
                continue

            if crds_cmd == "deleteroom":
                try:
                    self.deleteroom(chat_room_name)
                    print()
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

        # print("Response size bytes = ", response_size_bytes)
        if len(response_size_bytes) == 0:
            return

        # Make sure that you interpret it in host byte order.
        listing_size = int.from_bytes(response_size_bytes, byteorder='big')
        # print("Listing size = ", listing_size)
        if listing_size == 0:
            print("The chat directory is empty!\n")
            return

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
            print("The chat room does not exist!\n")
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
        self.chat_port = int(chat_room_port)

    def chatroom(self, name):
        try:
            self.connect_to_server()
        except Exception as msg:
            print(msg)
            print("Unable to retrieve multicast address/port for the associated chat room, please try again.\n")
            return

        try:
            self.getchat(name)
            self.get_socket()
        except Exception as msg:
            print(msg)
            print("Unable to retrieve multicast address/port for the associated chat room or connect to chat room, please try again.\n")
            self.socket.close()
            return

        try:
            self.receive_forever()
            return
        except Exception as msg:
            print(msg)
            print("Error connecting to chat room, please try again.")
            self.chat_socket.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP,
                                        socket.inet_aton(self.chat_address) + socket.inet_aton(RX_IFACE_ADDRESS))
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

        self.chat_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, TTL_BYTE)

    def receive_forever(self):
        print("Entering chat mode:")
        # Set stdin to non-blocking mode
        fd = sys.stdin.fileno()
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        while True:
            sockets_list = [sys.stdin, self.chat_socket]
            read_ready, write_ready, except_ready = select.select(sockets_list, [], [])

            for sock in read_ready:
                if sock == self.chat_socket:
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
                    self.chat_socket.sendto((self.chat_name + message).encode(MSG_ENCODING), (self.chat_address, self.chat_port))
                    # sys.stdout.write(self.chat_name + message)
                    # sys.stdout.flush()

                    # Check for exit command
                    if message.strip() == 'exit!':
                        print("Exitting chat room!\n")
                        self.chat_socket.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP,
                                                    socket.inet_aton(self.chat_address) + socket.inet_aton(RX_IFACE_ADDRESS))
                        self.chat_socket.close()

                        fd = sys.stdin.fileno()
                        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                        fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
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
