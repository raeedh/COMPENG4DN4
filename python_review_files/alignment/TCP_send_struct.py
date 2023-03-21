#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import struct

########################################################################
# Echo-Client class
########################################################################

class Client:

    SERVER = "localhost"
    PORT = 50000
    
    RECV_SIZE = 256

    ####################################################################
    # Manually create bytes with native struct padding.

    """

    si_le = (1).to_bytes(2, byteorder='little')
    pad   = (0).to_bytes(2, byteorder='little')
    i_le  = (2).to_bytes(4, byteorder='little')
    li_le = (3).to_bytes(8, byteorder='little')

    BYTES_TO_SEND = si_le + pad + i_le + li_le

    """

    ####################################################################
    # Send to struct using the Python struct module.

    si, i, li = (1, 2, 3)
    BYTES_TO_SEND = struct.pack('@hiq', si, i, li)

    def __init__(self):
        self.get_socket()
        self.connect_to_server()
        self.connection_send()

    def get_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connect_to_server(self):
        try:
            self.socket.connect((Client.SERVER, Client.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_send(self):
        try:
            self.socket.sendall(Client.BYTES_TO_SEND)
        except Exception as msg:
            print(msg)
            sys.exit(1)

########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    Client()
    
########################################################################






