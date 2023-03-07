import argparse
import csv
import socket
import sys
from typing import Dict

from cryptography.fernet import Fernet

HOSTNAME = "0.0.0.0"
PORT = 50007
MSG_ENCODING = "utf-8"
RECV_BUFFER_SIZE = 1024
MAX_CONNECTION_BACKLOG = 1
SOCKET_ADDRESS = (HOSTNAME, PORT)


class Server:
    def __init__(self):
        print("Server object created!")
        self.student_dict = {}
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.fernet = None

        self.process_csv_file()
        self.create_listen_socket()
        self.process_connections_forever()

    def process_csv_file(self):
        with open('course_grades_2023.csv', 'r') as csvfile:
            reader = csv.DictReader(csvfile)

            print("Data read from CSV file: ")

            for row in reader:
                print(row)
                self.student_dict[row["ID Number"]] = row

    def create_listen_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set socket layer socket options. This allows us to reuse the socket without waiting for any timeouts.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.socket.bind(SOCKET_ADDRESS)

            # Set socket to listen state.
            self.socket.listen(MAX_CONNECTION_BACKLOG)
            print(f"Listening for connections on port {PORT}")
            print()
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        try:
            while True:
                # Block while waiting for accepting incoming connections. When one is accepted, pass the new (cloned) socket reference to
                # the connection handler function.
                self.connection_handler(self.socket.accept())
        except Exception as msg:
            print(msg)
        finally:
            self.socket.close()
            sys.exit(1)

    def connection_handler(self, client):
        conn, addr = client
        print(f"Connection received from {addr[0]} on port {addr[1]}.")

        with conn:
            while True:
                try:
                    # Receive bytes over the TCP connection. This will block until "at least 1 byte or more" is available.
                    data: bytes = conn.recv(RECV_BUFFER_SIZE)

                    # If recv returns with zero bytes, the other end of the TCP connection has closed (The other end is probably in FIN
                    # WAIT 2 and we are in CLOSE WAIT.). If so, close the server end of the connection and get the next client connection.
                    if not data:
                        print("Closing client connection ... ")
                        print()
                        break

                    result = self.parse_data(data)

                    if not result:
                        print("Closing client connection ... ")
                        print()
                        break

                    conn.sendall(result)
                except:
                    print()
                    print("Closing client connection ... ")
                    print()
                    break

    def parse_data(self, data: bytes) -> bytes:
        match data.decode(MSG_ENCODING).split():
            case student_id, cmd:
                student: Dict = self.student_dict.get(student_id)

                print(f"Received {cmd} command from client.")

                if not student:
                    self.fernet = None
                    print("User not found.")
                    return b""

                print("User found.")
                # Re-assign the fernet encryption object based on the student id
                self.fernet = Fernet(student.get("Key").encode(MSG_ENCODING))

                return self.parse_cmd(cmd, student)
            case _:
                print("The provided data is improperly formatted!")
                return b""

    def parse_cmd(self, cmd: str, student: Dict) -> bytes:
        match cmd:
            case "GMA":
                return self.return_average("Midterm")
            case "GL1A":
                return self.return_average("Lab 1")
            case "GL2A":
                return self.return_average("Lab 2")
            case "GL3A":
                return self.return_average("Lab 3")
            case "GL4A":
                return self.return_average("Lab 4")
            case "GEA":
                values = self.student_dict.values()

                exam1_sum, exam2_sum, exam3_sum, exam4_sum = 0, 0, 0, 0

                for value in values:
                    exam1_sum += int(value["Exam 1"])
                    exam2_sum += int(value["Exam 2"])
                    exam3_sum += int(value["Exam 3"])
                    exam4_sum += int(value["Exam 4"])

                ret_msg = f"Exam 1 Average: {exam1_sum / len(values)}, Exam 2 Average: {exam2_sum / len(values)}, Exam 3 Average: " \
                          f"{exam3_sum / len(values)}, Exam 4 Average: {exam4_sum / len(values)}"

                return self.send_message(ret_msg)
            case "GG":
                ret_msg = f"Lab 1: {int(student.get('Lab 1'))}, Lab 2: {int(student.get('Lab 2'))}, Lab 3: {int(student.get('Lab 3'))}, " \
                          f"Lab 4: {int(student.get('Lab 4'))}, Midterm: {int(student.get('Midterm'))}, Exam 1: " \
                          f"{int(student.get('Exam 1'))}, Exam 2: {int(student.get('Exam 2'))}, Exam 3: {int(student.get('Exam 3'))}, " \
                          f"Exam 4: {int(student.get('Exam 4'))}"

                return self.send_message(ret_msg)
            case _:
                print("Invalid command!")
                return b""

    def return_average(self, key: str):
        values = self.student_dict.values()
        average = sum([int(value[key]) for value in values]) / len(values)
        return self.send_message(f"{key} Average: {average}")

    def send_message(self, message: str):
        encrypted_message_bytes = self.fernet.encrypt(message.encode(MSG_ENCODING))
        print("encrypted_message_bytes = ", encrypted_message_bytes)
        return encrypted_message_bytes


class Client:
    # Set the server to connect to. If the server and client are running on the same machine, we can use the current hostname.
    SERVER_HOSTNAME = "localhost"
    # List of valid commands
    CMDS = {"GMA": "Fetching Midterm average:",
            "GL1A": "Fetching Lab 1 average:",
            "GL2A": "Fetching Lab 2 average:",
            "GL3A": "Fetching Lab 3 average:",
            "GL4A": "Fetching Lab 4 average:",
            "GEA": "Fetching Exam average:",
            "GG": "Getting Grades:"
            }

    def __init__(self):
        print("Client object created!")

        self.encryption_key_dict = {
            "1803933": "M7E8erO15CIh902P8DQsHxKbOADTgEPGHdiY0MplTuY=",
            "1884159": "PWMKkdXW4VJ3pXBpr9UwjefmlIxYwPzk11Aw9TQ2wZQ=",
            "1853847": "UVpoR9emIZDrpQ6pCLYopzE2Qm8bCrVyGEzdOOo2wXw=",
            "1810192": "bHdhydsHzwKdb0RF4wG72yGm2a2L-CNzDl7vaWOu9KA=",
            "1891352": "iHsXoe_5Fle-PHGtgZUCs5ariPZT-LNCUYpixMC3NxI=",
            "1811313": "IR_IQPnIM1TI8h4USnBLuUtC72cQ-u4Fwvlu3q5npA0=",
            "1804841": "kE8FpmTv8d8sRPIswQjCMaqunLUGoRNW6OrYU9JWZ4w=",
            "1881925": "_B__AgO34W7urog-thBu7mRKj3AY46D8L26yedUwf0I=",
            "1877711": "dLOM7DyrEnUsW-Q7OM6LXxZsbCFhjmyhsVT3P7oADqk=",
            "1830894": "aM4bOtearz2GpURUxYKW23t_DlljFLzbfgWS-IRMB3U=",
            "1855191": "-IieSn1zKJ8P3XOjyAlRcD2KbeFl_BnQjHyCE7-356w=",
            "1821012": "Lt5wWqTM1q9gNAgME4T5-5oVptAstg9llB4A_iNAYMY=",
            "1844339": "M6glRgMP5Y8CZIs-MbyFvev5VKW-zbWyUMMt44QCzG4=",
            "1898468": "SS0XtthxP64E-z4oB1IsdrzJwu1PUq6hgFqP_u435AA=",
            "1883633": "0L_o75AEsOay_ggDJtOFWkgRpvFvM0snlDm9gep786I=",
            "1808742": "9BXraBysqT7QZLBjegET0e52WklQ7BBYWXvv8xpbvr8=",
            "1863450": "M0PgiJutAM_L9jvyfrGDWnbfJOXmhYt_skL0S88ngkU=",
            "1830190": "v-5GfMaI2ozfmef5BNO5hI-fEGwtKjuI1XcuTDh-wsg=",
            "1835544": "LI14DbKGBfJExlwLodr6fkV4Pv4eABWkEhzArPbPSR8=",
            "1820930": "zoTviAO0EACFC4rFereJuc0A-99Xf_uOdq3GiqUpoeU="
        }

        self.get_console_input()

    def get_console_input(self):
        while True:
            self.user_input = input("Enter the student ID number, followed by an applicable command (e.g. 1234567 GMA): ")

            try:
                self.student_id, self.cmd = self.user_input.split()
            except Exception:
                print("The input is invalid, please try again.")
                continue

            if (not self.student_id.isdigit()) or (len(self.student_id) != 7) or (self.cmd not in Client.CMDS):
                print("The student ID or command is invalid.")
                continue

            print("Student ID:", self.student_id)
            print("Command received:", self.cmd)
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
        print(f"Connected to {Client.SERVER_HOSTNAME} on port {PORT}")
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
            print(Client.CMDS.get(self.cmd))
            # Receive and print out text. The received bytes objects must be decoded into string objects.
            recvd_bytes = self.socket.recv(RECV_BUFFER_SIZE)

            # recv will block if nothing is available. If we receive zero bytes, the connection has been closed from the other end. In
            # that case, close the connection on this end and exit.
            if len(recvd_bytes) == 0:
                print("Did not receive message from server, closing server connection ... ")
                print()
            else:
                fernet = Fernet(self.encryption_key_dict.get(self.student_id).encode(MSG_ENCODING))

                decrypted_message_bytes = fernet.decrypt(recvd_bytes)
                decrypted_message = decrypted_message_bytes.decode(MSG_ENCODING)
                # print("The message received back from the server is:", recvd_bytes)
                print(decrypted_message)
                print()

            self.socket.close()
        except Exception as msg:
            print(msg)
            print("Error receiving message from server, please try again.")


if __name__ == '__main__':
    roles = {'client': Client, 'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role', choices=roles, help='server or client role', required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()
