#!/bin/python
# coding: utf-8

import requests
import sys
from Queue import Queue
from threading import Thread
from optparse import OptionParser
from bs4 import BeautifulSoup

VERBOSE_MODE = False
q = Queue()


def worker():
    global q
    global BEEP

    while True:
        # get the resource
        resource = q.get().rstrip()

        print 'Hash %s' % resource
        # Randomly choose a User-agent
        url = 'https://www.virustotal.com/en/file/%s/analysis/' % resource
        user_agent = {'User-agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:33.0) Gecko/20100101 Firefox/33.0'}
        req = requests.get(url, headers=user_agent)
        soup = BeautifulSoup(req.content)
        behavioural_info = soup.find('div', attrs={'id': 'behavioural-info'})
        for url in behavioural_info.findAll('strong'):
            print '\t' + url.text

        q.task_done()


def display_message(s):
    global VERBOSE_MODE
    if VERBOSE_MODE:
        print '[verbose] %s' % s


def main():
    global VERBOSE_MODE
    global q

    parser = OptionParser()
    parser.add_option("-t", "--threads", dest="threads", default=10, help="Number of threads (default 10)")
    parser.add_option("-F", "--list", dest="hashes", help="List of hashes to test for", default=None)
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="Verbose mode")

    (options, args) = parser.parse_args()

    if options.verbose:
        VERBOSE_MODE = True

    if not options.hashes:
        print parser.print_help()
        sys.exit(-1)

    if (options.hashes):
        with open(options.hashes) as f:
            hashes = f.readlines()
    else:
        hashes = [options.file]
    display_message('Loading %s hashes(s)' % len(hashes))

    # instantiating the queue
    for i in range(int(options.threads)):
        t = Thread(target=worker)
        t.daemon = True
        t.start()

    # inserting all elems
    for hash_to_try in hashes:
        q.put(hash_to_try)

    q.join()

if __name__ == '__main__':
    main()
