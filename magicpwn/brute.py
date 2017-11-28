#!/usr/bin/env python

import multiprocessing as mp
import time
import itertools
import string

# Set the list to iterate: string.ascii_letters, ascii_lowercase, ascii_uppercase, digits, hexdigits, punctuation, printable, whitespace
CHARSET = string.printable
# Set the number of threads
THREADS = 4


results = []
def bruteForcer(first, alphabet, name, arg):
    print "Starting " + name
    for x in itertools.product(first, alphabet, alphabet, alphabet, alphabet):
        doWork(x, arg)
    print "Done " + name
    return None

def collectResult(result):
    results.extend(result)

def startThreads(arg):
    tpool = mp.Pool(processes=THREADS)
    sub_len = len(CHARSET) // THREADS
    threads = []
    for i in range(THREADS):
        if i < THREADS - 1:
            tpool.apply_async(bruteForcer, args=(CHARSET[i * sub_len: (i + 1) * sub_len], CHARSET, "worker"+str(i), arg), callback = collectResult)

        else:
            tpool.apply_async(bruteForcer, args=(CHARSET[i * sub_len:], CHARSET, "worker"+str(i), arg), callback = collectResult)

    print "Workers are started!"
    tpool.close()
    tpool.join()
    print "Workers are done!"
    return results

def doWork(x, arg):
    pass

if __name__ == "__main__":
    arg = None

    result = startThreads(arg)
    # Results are ready
    print result
    print "Main Thread done"

