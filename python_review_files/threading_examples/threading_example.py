#!/usr/bin/env python3

########################################################################
# Illustration of Python Threading Parallelism.
########################################################################

import threading
import time

THREADS_ENABLED = False
# THREADS_ENABLED = True
NUMBER_OF_TASKS = 10

def handler(i):
    print("Thread {} starting: {}".format(i, threading.current_thread().name))

    # Pretend to do some real work.
    time.sleep(2)
    print('Thread {} ending: {}'.format(i, threading.current_thread().name))
    return

thread_list = []

for i in range(NUMBER_OF_TASKS):
    if THREADS_ENABLED:
        # Generate a custom name for each of our threads.
        new_thread_name = "my_thread_" + str(i)

        # Create a new thread, add it to the thread list, then start
        # its execution.
        new_thread = threading.Thread(target=handler, name=new_thread_name, args=(i,))
        thread_list.append(new_thread)
        new_thread.start()
    else:
        # If threads are not enabled, call the handler, one at a time.
        handler(i)

# Use join() to have the main thread wait until all created threads
# have completed (only needed if threads are daemonic).
print("Waiting for thread completion ...")
if THREADS_ENABLED:
    for thread in thread_list:
        thread.join()

# Let everyone know that we are done!
print("All threads finished!")





