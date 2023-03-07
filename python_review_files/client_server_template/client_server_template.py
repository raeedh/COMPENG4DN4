#!/usr/bin/env python3

########################################################################

import argparse

########################################################################

class Server:
    def __init__(self):
        print("We have created a Server object: ", self)
        pass

class Client:
    def __init__(self):
        print("We have created a Client object: ", self)    
        pass

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


# i.e., use "... -r client" or "... -r server" to run the client or server,
# respectively.

########################################################################






