#!/usr/bin/env python3

# Illustrate the value of __name__ in local and external imported
# python scripts.

local_name = "John Smith"

print("*"*72)

## Print out the value of __name__ in this script.
##
print("Inside script.py: __name__ = \"{}\"".format(__name__))
print("*"*72)

# Try both True and False:
COMMON_NAMESPACE = True
# COMMON_NAMESPACE = False

if COMMON_NAMESPACE:

    from external_module import *

    print("*"*72)
    print("local_name = {}".format(local_name))
    print("external_name = {}".format(external_name))
        
else:

    import external_module

    print("*"*72)
    print("local_name = {}".format(local_name))
    print("external_module.external_name = {}".format(external_module.external_name))    




    












