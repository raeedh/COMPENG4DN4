#!/usr/bin/python3

########################################################################
# Illustration of daemon vs non-daemon threads.
########################################################################

import threading
import time

########################################################################

thread_list = []

NUMBER_OF_THREADS = 5
SLEEP_BEFORE_EXITING = False
# SLEEP_BEFORE_EXITING = True

case = 1

if case == 1:
    RUN_EACH_THREAD_FOREVER = True
    DAEMON_THREADS = True
    WAIT_FOR_ALL_THREAD_COMPLETION = False
elif case == 2:
    RUN_EACH_THREAD_FOREVER = False
    DAEMON_THREADS = True
    WAIT_FOR_ALL_THREAD_COMPLETION = False
elif case == 3:
    RUN_EACH_THREAD_FOREVER = False
    DAEMON_THREADS = True
    WAIT_FOR_ALL_THREAD_COMPLETION = True
elif case == 4:
    RUN_EACH_THREAD_FOREVER = False
    DAEMON_THREADS = False
    WAIT_FOR_ALL_THREAD_COMPLETION = False

########################################################################

def handler(i):
    print("Thread {} ({}) starting: ".format(i, threading.current_thread().name))
    while True:
        ################################################################        
        # Pretend to do some real work.
        time.sleep(5)
        ################################################################
        # RUN EACH THREAD FOREVER or not
        if not RUN_EACH_THREAD_FOREVER:
            print("Thread {} ({}) stopping: ".format(i, threading.current_thread().name))
            break

########################################################################
        
for i in range(NUMBER_OF_THREADS):

    # Generate a custom name for each of our threads.
    new_thread_name = "my_thread_" + str(i)
    
    # Create a new thread, add it to the thread list, then start
    # its execution.
    new_thread = threading.Thread(target=handler, name=new_thread_name, args=(i,))
    thread_list.append(new_thread)    

    ####################################################################
    # Set DAEMON THREADS or not.
    new_thread.daemon = DAEMON_THREADS
    new_thread.start()

########################################################################    
# Use join() to have the main thread wait until all created threads
# have completed.

if WAIT_FOR_ALL_THREAD_COMPLETION:
    print("Waiting for thread completion ...")
    for thread in thread_list:
        thread.join()

########################################################################        
# Instead of keeping a thread list of our own, we can obtain one from
# threading.enumerate(). Then synchronize them. Note that this list
# includes the main thread that we need to test for.
# for thread in threading.enumerate():
#    if thread is threading.main_thread():
#       continue
#    else:
#       thread.join()

if SLEEP_BEFORE_EXITING:
    time.sleep(10)

########################################################################    
# Tell everyone that we are at the end of our script.
print("End of script!")





