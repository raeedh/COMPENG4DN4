#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import threading

# Use the standard echo client.
from EchoClientServer import Client

########################################################################
# Echo Server class
########################################################################

class Server:

    HOSTNAME = "0.0.0.0" # socket.gethostname()
    PORT = 50000

    RECV_SIZE = 256
    BACKLOG = 10
    
    MSG_ENCODING = "utf-8"

    def __init__(self):
        self.thread_list = []
        self.create_listen_socket()
        self.process_connections_forever()

    def create_listen_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Get socket layer socket options.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.socket.bind( (Server.HOSTNAME, Server.PORT) )

            # Set socket to listen state.
            self.socket.listen(Server.BACKLOG)
            print("Listening on port {} ...".format(Server.PORT))

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        try:
            while True:
                new_client = self.socket.accept()

                # A new client has connected. Create a new thread and
                # have it process the client using the connection
                # handler function.
                new_thread = threading.Thread(target=self.connection_handler,
                                              args=(new_client,))

                # Record the new thread.
                self.thread_list.append(new_thread)

                # Start the new thread running.
                print("Starting serving thread: ", new_thread.name)
                new_thread.daemon = True
                new_thread.start()

        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            print("Closing server socket ...")
            self.socket.close()
            sys.exit(1)

    def connection_handler(self, client):
        connection, address_port = client
        print("-" * 72)
        print("Connection received from {}.".format(address_port))

        while True:
            # Receive bytes over the TCP connection. This will block
            # until "at least 1 byte or more" is available.
            recvd_bytes = connection.recv(Server.RECV_SIZE)
            
            # If recv returns with zero bytes, the other end of the
            # TCP connection has closed (The other end is probably in
            # FIN WAIT 2 and we are in CLOSE WAIT.). If so, close the
            # server end of the connection and get the next client
            # connection.
            if len(recvd_bytes) == 0:
                print("Closing {} client connection ... ".format(address_port))
                connection.close()
                # Break will exit the connection_handler and cause the
                # thread to finish.
                break
                
            # Decode the received bytes back into strings. Then output
            # them.
            recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
            print("Received: ", recvd_str)
                
            # Send the received bytes back to the client.
            connection.sendall(recvd_bytes)
            print("Sent: ", recvd_str)

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






