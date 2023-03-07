import argparse
import socket

from cryptography.fernet import Fernet
import csv

fernet = Fernet()

class Server:
    def __init__(self):
        print("We have created a Server object: ", self)

        with open('course_grades_2023.csv', 'r') as csvfile:
            self.course_grades = csv.reader(csvfile)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('', 50007))
        self.socket.listen(1)

    def send_message(self, message: str):
        encrypted_message_bytes = fernet.encrypt(message.encode('utf-8'))


class Client:
    def __init__(self):
        print("We have created a Client object: ", self)
        pass


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
