#!/usr/bin/python3

########################################################################
# Illustration of Python Threading Parallelism.
########################################################################

import threading
import time
import sys
import os
import subprocess

########################################################################

THREADS_ENABLED = False
# THREADS_ENABLED = True

HOST_LIST = [
    "www.yahoo.com",
    "www.microsoft.com",
    "localhost",
    "www.google.com",
    "www.ece.mcmaster.ca",
    "owl.ece.mcmaster.ca",
    "www.mcmaster.ca"
] 

########################################################################

def handler(host):
    cmd = "ping -c 5 " + host
    result = os.popen(cmd).readlines()

    if "Unreachable" in "".join(result):
        print(host + " is offline.")
    else:
        print(host + " is online.")

    # print(result)
    sys.stdout.flush()
    return

########################################################################

thread_list = []

for host in HOST_LIST:
    if THREADS_ENABLED:
        # Generate a custom name for each of our threads.
        new_thread_name = "coe4dn4_thread_" + str(host)

        # Create a new thread, add it to the thread list, then start
        # its execution.
        new_thread = threading.Thread(target=handler, name=new_thread_name, args=(host,))
        new_thread.daemon = True
        thread_list.append(new_thread)

        print("Starting new thread: ", new_thread_name);
        sys.stdout.flush()
        new_thread.start()
    else:
        # If threads are not enabled, call the handler, one at a time.
        handler(host)

# Use join() to have the main thread wait until all created threads
# have completed and reported their output.
if THREADS_ENABLED:
    for thread in thread_list:
        thread.join()

# Let everyone know that we are done!
print("All finished!")





