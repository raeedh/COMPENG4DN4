#!/usr/bin/env python3

"""An example module for creating Company objects. The Company object
includes an employees dictionary that includes person objects.

"""

########################################################################

import argparse
from person import *

########################################################################

class Company:

    def __init__(self, name, employee_database_file):
        """Create a Company object by calling it with the name of the company
        and employee database file.

        e.g., new_company = Company("New Company Name Inc.",
        "database_file.txt"). If the file does not exist, it will be
        created.

        """
        # Record the company name.
        self.name = name
        # Set database file instance variable.
        self.employee_database_file = employee_database_file

        # Create an empty dictionary of the employees.
        self.employees = {}
        # Keep track of the next employee id to assign.
        self.next_employee_id = 1000 # Default value.

        # Read in and process the employee database.
        self.import_employee_database()

    def import_employee_database(self):
        """Read in the employee database, clean whitespace from each record,
        parse them and create the employee dictionary.

        """
        # Read in the employee database and clean whitespace from each
        # record.
        self.read_and_clean_database_records()

        # Read each line and parse the employee id_number, first, and
        # last name.
        self.parse_employee_records()

        # Create people records and add them to the company employee
        # dictionary.
        self.create_employee_dictionary()      

        # Set the next_employee_id number to assign.
        try:
            self.next_employee_id = 1 + max(self.employees.keys())
        except ValueError:
            pass

    def read_and_clean_database_records(self):
        """Read a list of people from a database file and add them as
        employees to the company.

        Open the file and read in the lines, stripping off end-of-line
        characters. Ignore blank lines.

        """
        try:
            file = open(self.employee_database_file, "r")
        except FileNotFoundError:
            print("Creating database: {}". format(self.employee_database_file))
            file = open(self.employee_database_file, "w+")

        # Read and process all non-blank lines in the file. The
        # following uses two list comprehensions.
        self.cleaned_records = [clean_line for clean_line in
                                [line.strip() for line in file.readlines()]
                                if clean_line != '']

        file.close()
         
        # Or (using a generator):
        # file_lines = [line for line in
        #               (line.strip() for line in file.readlines())
        #               if line != '']
        # Or (requires to line.strip()s:
        # file_lines = [line.strip() for line in file.readlines() if
        # line.strip() != '']
        # print(file_lines)

    def parse_employee_records(self):
        """Split each line into employee id number, first and last
        names. 

        self.employee_list is a three-tuple containing these
        values. Convert the id number into an int.

        """
        try:
            self.employee_list = [
                (int(e[0].strip()), e[1].strip(), e[2].strip()) for e in
                [e.split(',') for e in self.cleaned_records]]
        except Exception:
            print("Error: Invalid people name input file.")
            exit()

    def create_employee_dictionary(self):
        """Add everyone to the company employee list."""
        for employee in self.employee_list:
            # Try to make a new Employee object. First check if we are given
            # first and last names.
            try:
                # Try to unpack the provided tuple.
                id_number, fname, lname = employee
                # Create a new Person object.
                new_person = Person(first_name=fname, last_name=lname)
                # Add the Person object to the company employee list. The company
                # employee list is a python dictionary of employee objects keyed
                # by employee id number.
                self.add_employee(int(id_number), new_person)
                # Print out the company object dictionary.
                # print(newco.__dict__)
                # exit()
            except Exception:
                # We caught an exception. Give up and complain.
                print("Error: Name \"{}\" is not fully specified.".format(new_person))
                self.ask_to_save_database()                

        # Print the names of all company employees.
        # print(self.employees)
        # self.print_employees()
        # exit()

    def add_employee(self, id_number=None, person=None):
        """Add a new Person object to a Company object employee list, e.g.,
        new_company.add_employee(person).

        """
        if id_number:
            self.employees[id_number] = person
        else:
            self.employees[self.next_employee_id] = person
            self.next_employee_id += 1

    def delete_employee(self, employee_id):
        """Delete an employee object from a Company object employees
        dictionary, e.g., new_company.delete_employee(employee_id).

        """
        del self.employees[employee_id]

    def size(self):
        # Get the size of the company (in employees), e.g.,
        # company_size = Company.size
        return(len(self.employees))

    def get_employee_name_list(self):
        return list(self.employees.values())

    def print_employees(self):
        print("\nEmployees: (Size: {})\n".format(self.size()))
        for id, p in self.employees.items():
            print("id: {} First Name: \"{}\" Last Name: \"{}\""
                  .format(id, p.first_name, p.last_name))
        print()

    def ask_to_save_database(self):
        answer = input("Save database? (y/N): ")
        if answer == "y":
            try:
                file = open(self.employee_database_file, "w")
                for key in self.employees.keys():
                    # Create a CSV record for the database.
                    record = str(key) + "," + \
                             self.employees[key].first_name + "," + \
                             self.employees[key].last_name + "\n"
                    file.write(record)
            finally:
                file.close()
        
    def enter_new_employees(self):
        """Prompt the user console for new employees and add them to the
        employee dictionary.

        """
        # Output the current database.
        self.print_employees()        
        while True:

            # Prompt the user for a new employee first name.
            fname = input("First name (\"q\" to quit): ").strip()
            # Restart the loop if a blank line is entered.            
            if not fname:
                continue
            # We are finished if a "q" is entered.
            elif fname == "q":
                self.ask_to_save_database()
                break

            # Prompt the user for a new employee last name.            
            lname = input("Last name (\"q\" to quit): ").strip()
            # Restart the loop if a blank line is entered.
            if not lname:
                continue
            # We are finished if a "q" is entered.
            elif lname == "q":
                self.ask_to_save_database()
                break

            try:
                # Create an object for the provided name. And add it
                # to the employee list.
                new_person = Person(first_name=fname, last_name=lname)
                self.add_employee(person=new_person)
                self.print_employees()
            except Exception:
                # We caught an exception. Give up and complain.
                print("Error: Name is not properly specified.")

    def remove_employees(self):
        """Prompt the user console for employees to remove from the employee
        dictionary.

        """
        while True:
            self.print_employees()
            # Prompt the user for an employee's id.
            employee_id = input("Delete employee ID: (\"q\" to quit): ").strip()
            # Restart the loop if a blank line is entered.                
            if not employee_id:
                continue
            # We are finished if a "q" is entered.            
            elif employee_id == "q":
                self.ask_to_save_database()
                break
            try:
                # Try to delete this employee. 
                self.delete_employee(int(employee_id))
                self.print_employees()
            except Exception:
                # We caught an exception. Give up and complain.
                print("Error: Employee ID error.")

#######################################################################
# Process command line arguments if this module is run directly.
########################################################################

# When the python interpreter runs this module directly (rather than
# importing it into another file) it sets the __name__ variable to a
# value of "__main__". If this file is imported from another module,
# then __name__ will be set to that module's name.

if __name__ == "__main__":

    ####################################################################    
    # If invoked directly as a script, create a default company and
    # import its employee database.

    # Create a default company name.
    COMPANY_NAME = "Default Incorporated"

    # Define the default employee database file.
    EMPLOYEE_FILE = "./default_employee_database.txt"

    # Print out a 72 character divider line.
    print("-" * 72)

    # Create a new company and import its database.
    company = Company(COMPANY_NAME, EMPLOYEE_FILE)
    print("Company Name: \"{}\".".format(company.name))

    # Print out a 72 character divider line.
    print("-" * 72)

    ####################################################################
    # Use argparse module.
    
    functions = {
        'add':    company.enter_new_employees,
        'delete': company.remove_employees,
        'view':   company.print_employees
    }

    parser = argparse.ArgumentParser()

    parser.add_argument('-f', '--function',
                        choices=functions, 
                        help='view, add or delete default company employees',
                        required=True, type=str)

    args = parser.parse_args()
    functions[args.function]()

########################################################################


        
