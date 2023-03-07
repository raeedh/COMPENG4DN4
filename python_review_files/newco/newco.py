#!/usr/bin/env python3

"""A script showing some examples using the company module.

"""

import argparse

# Start by importing the Python modules that we need.
from company import *
# Alternately: "import company" (but then we must prefix all
# method invocations with "company".

########################################################################
# Print out a 72 character divider line.
def print_divider_line():
    print("-" * 72)
########################################################################    

# Define a company name constant (e.g., all caps).
COMPANY_NAME = "Newco Incorporated"

# Define the employee database file.
EMPLOYEE_FILE = "./newco_employee_database.txt"
 
########################################################################
print_divider_line()
########################################################################

# Create a new company and import its database.
newco = Company(COMPANY_NAME, EMPLOYEE_FILE)
print("Company Name: \"{}\".".format(newco.name))

########################################################################
print_divider_line()
########################################################################

newco.enter_new_employees()
newco.remove_employees()
# newco.print_employees()

########################################################################


