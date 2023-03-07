import argparse
import socket

from cryptography.fernet import Fernet
import csv

fernet = Fernet(Fernet.generate_key())
PORT = 50007

class Server:
    def __init__(self):
        print("Server object created!")

        with open('course_grades_2023.csv', 'r') as csvfile:
            reader = csv.reader(csvfile)

            print("Data read from CSV file: ")

            for row in reader:
                print(row)

        # self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.socket.bind(('', PORT))
        # self.socket.listen(1)
        print(f"Listening for connections on port {PORT}")

    def send_message(self, message: str):
        encrypted_message_bytes = fernet.encrypt(message.encode('utf-8'))


class Client:
    # Set the server to connect to. If the server and client are running
    # on the same machine, we can use the current hostname.
    SERVER_HOSTNAME = "localhost"
    # List of valid commands
    CMDS = ["GMA", "GL1A", "GL2A", "GL3A", "GL4A", "GEA", "GG"]

    RECV_BUFFER_SIZE = 1024 # Used for recv.

    def __init__(self):
        print("We have created a Client object: ", self)
        self.get_console_input()

        pass

    def get_console_input(self):
        while True:
            self.user_input = input("Enter the student ID number, followed by an applicable command (e.g. 1234567 GMA): ")
            student_id, cmd = self.user_input.split()

            if (not student_id.isdigit()) or (len(student_id) != 7) or (cmd not in Client.CMDS):
                print("The student ID or command is invalid")
                continue
            
            print("Student ID:", student_id)
            print("Command received:", cmd)
            print()

            try:
                self.connect_to_server()
            except Exception as msg:
                print(msg)
                print("Error connecting to server, please try again.")
                print()
                continue

            try:
                self.connection_send()
                self.connection_receive()
            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                # If we get and error or keyboard interrupt, make sure
                # that we close the socket.
                self.socket.close()

    def connect_to_server(self):
        # Create an IPv4 TCP socket.
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to the server using its socket address tuple.
        self.socket.connect((Client.SERVER_HOSTNAME, Server.PORT))
        print("Connected to \"{}\" on port {}".format(Client.SERVER_HOSTNAME, Server.PORT))
        print()
    
    def connection_send(self):
        try:
            # Send string objects over the connection. The string must
            # be encoded into bytes objects first.
            self.socket.sendall(self.user_input.encode(Server.MSG_ENCODING))
        except Exception as msg:
            print(msg)
            print("Error sending message to server, please try again.")

    def connection_receive(self):
        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)

            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end. In that case, close the connection on this
            # end and exit.
            if len(recvd_bytes) == 0:
                print("Did not receive message from server, closing server connection ... ")
                self.socket.close()
            else:
                decrypted_message_bytes = fernet.decrypt(recvd_bytes)
                decrypted_message = decrypted_message_bytes.decode('utf-8')
                print("decrypted_message = ", decrypted_message)

            print("Received: ", recvd_bytes.decode(Server.MSG_ENCODING))

        except Exception as msg:
            print(msg)
            print("Error receiving message from server, please try again.")

    def run_command(self):
        # send command to server via socket

        decrypted_message_bytes = fernet.decrypt()  # TODO: add the message that we get from the socket as a param
        decrypted_message = decrypted_message_bytes.decode('utf-8')


if __name__ == '__main__':
    roles = {'client': Client, 'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role', choices=roles, help='server or client role', required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()
