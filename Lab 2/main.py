import argparse
import socket
from typing import Dict

from cryptography.fernet import Fernet
import csv

fernet = None
PORT = 50007


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
                    data: bytes = conn.recv(1024)

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
                fernet = Fernet(student.get("key").encode('utf-8'))

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
        encrypted_message_bytes = fernet.encrypt(message.encode('utf-8'))
        self.socket.sendall(encrypted_message_bytes)


class Client:
    def __init__(self):
        print("Client object created!")

        self.id = input("Please enter your student ID: ")

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
