import argparse
import csv
import socket
from typing import Dict

from cryptography.fernet import Fernet

fernet = None
PORT = 50007
MSG_ENCODING = "utf-8"
RECV_BUFFER_SIZE = 1024


class Server:
    def __init__(self):
        print("Server object created!")
        self.student_dict = None
        self.socket = None

        self.process_csv_file()
        self.start_listening()

    def process_csv_file(self):
        with open('course_grades_2023.csv', 'r') as csvfile:
            reader = csv.reader(csvfile)

            print("Data read from CSV file: ")

            rows = []

            for row in reader:
                rows.append(row)
                print(row)

        self.student_dict = {}

    def start_listening(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('', PORT))
        self.socket.listen(1)
        print(f"Listening for connections on port {PORT}")

        while True:
            conn, addr = self.socket.accept()

            with conn:
                while True:
                    data: bytes = conn.recv(RECV_BUFFER_SIZE)

                    if not data:
                        break

                    result = self.parse_data(data)

                    if not result:
                        break

    def parse_data(self, data: bytes) -> bool:
        match data.split():
            case student_id, cmd:
                global fernet
                student: Dict = self.student_dict.get(student_id)

                if not student:
                    fernet = None
                    print("User not found.")
                    return False

                print("User found.")
                # Re-assign the fernet encryption object based on the student id
                fernet = Fernet(student.get("key").encode(MSG_ENCODING))

                return self.parse_cmd(cmd)
            case _:
                print("The provided data is improperly formatted!")
                return False

    def parse_cmd(self, cmd: bytes) -> bool:
        match cmd:
            case b"GMA":
                return True
            case b"GL1A":
                return True
            case b"GL2A":
                return True
            case b"GL3A":
                return True
            case b"GL4A":
                return True
            case b"GEA":
                return True
            case b"GG":
                return True
            case _:
                print("Invalid command!")
                return False

    def send_message(self, message: str):
        encrypted_message_bytes = fernet.encrypt(message.encode(MSG_ENCODING))
        self.socket.sendall(encrypted_message_bytes)


class Client:
    # Set the server to connect to. If the server and client are running on the same machine, we can use the current hostname.
    SERVER_HOSTNAME = "localhost"
    # List of valid commands
    CMDS = ["GMA", "GL1A", "GL2A", "GL3A", "GL4A", "GEA", "GG"]

    def __init__(self):
        print("We have created a Client object: ", self)
        self.get_console_input()

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
                # If we get an error or keyboard interrupt, make sure that we close the socket.
                self.socket.close()

    def connect_to_server(self):
        # Create an IPv4 TCP socket.
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to the server using its socket address tuple.
        self.socket.connect((Client.SERVER_HOSTNAME, PORT))
        print("Connected to \"{}\" on port {}".format(Client.SERVER_HOSTNAME, PORT))
        print()

    def connection_send(self):
        try:
            # Send string objects over the connection. The string must be encoded into bytes objects first.
            self.socket.sendall(self.user_input.encode(MSG_ENCODING))
        except Exception as msg:
            print(msg)
            print("Error sending message to server, please try again.")

    def connection_receive(self):
        try:
            # Receive and print out text. The received bytes objects must be decoded into string objects.
            recvd_bytes = self.socket.recv(RECV_BUFFER_SIZE)

            # recv will block if nothing is available. If we receive zero bytes, the connection has been closed from the other end. In
            # that case, close the connection on this end and exit.
            if len(recvd_bytes) == 0:
                print("Did not receive message from server, closing server connection ... ")
                self.socket.close()
            else:
                decrypted_message_bytes = fernet.decrypt(recvd_bytes)
                decrypted_message = decrypted_message_bytes.decode(MSG_ENCODING)
                print("decrypted_message = ", decrypted_message)

            print("Received: ", recvd_bytes.decode(MSG_ENCODING))
        except Exception as msg:
            print(msg)
            print("Error receiving message from server, please try again.")


if __name__ == '__main__':
    roles = {'client': Client, 'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role', choices=roles, help='server or client role', required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()
