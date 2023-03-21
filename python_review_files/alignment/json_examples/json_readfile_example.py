#!/usr/bin/env python3

########################################################################

import json
import pprint

########################################################################

DATABASE = "json_employee_database.txt"

# Open and read in the database as a text file.
json_file = open(DATABASE, 'r')
json_data = json_file.read()

# Interpret the JSON.
data_object = json.loads(json_data)

print(type(data_object))
print(data_object)

# pp = pprint.PrettyPrinter(indent=4)
# pp.pprint(data_object)


