from cryptography.fernet import Fernet
import csv

class Server:
    def __init__(self):
        with open('course_grades_2023.csv', 'r') as csvfile:
            course_grades = csv.reader(csvfile)


class Client:
    pass


def main():
    pass


if __name__ == '__main__':
    main()
