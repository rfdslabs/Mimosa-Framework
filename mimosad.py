#!/usr/bin/python3
#
# Mimosa v1.0a
# "Julio Auto"<julio@julioauto.com>
#
# This program was developed to use pymongo 2.2, which, although outdated, is
# the current version available for Debian/Kali, at time of writing.
# 
# Update 11 Dec 2024
# Mimosa v2.0a GPT/Claude

from daemon import Daemon
from pymongo import MongoClient
import sched
import time
import sys
import os
import logging
import threading
import urllib.request
import tempfile
from cisco_epc import start_epc, stop_epc, collect_epc

PIDFILE = '/var/run/mimosad.pid'
LOGFILE = '/var/log/mimosad.log'
LOGLEVEL = logging.DEBUG
OP_TIMEOUT = 120
DL_DIR = '/tmp'
DL_THRESHOLD = 50
COMMANDS = ['start', 'stop', 'restart']

def pop_ftp(url, mimosad):
    """Fetch a file from FTP."""
    with mimosad.filelock:
        if url in mimosad.files:
            mimosad.files.remove(url)

    try:
        tmp = tempfile.mkstemp(dir=DL_DIR)
        os.close(tmp[0])
        urllib.request.urlretrieve(url, tmp[1])
        logging.info(f'{url} downloaded to {tmp[1]}')
    except Exception as e:
        logging.error(f'Error downloading {url}: {e}')

class Mimosad(Daemon):
    def __init__(self, pidfile):
        super().__init__(pidfile)
        try:
            self.dbconn = MongoClient()
            self.s = sched.scheduler(time.time, time.sleep)
            logging.basicConfig(format='[%(asctime)s][%(levelname)s] %(message)s', filename=LOGFILE, level=LOGLEVEL)
            self.epc_children = {}
            self.url_children = {}
            self.files = []
            self.filelock = threading.RLock()
        except Exception as e:
            logging.error(f'Error during initialization: {e}')
            sys.exit(1)

    def get_db(self):
        """Get the database connection."""
        try:
            self.dbconn.admin.command('ping')  # Test connection
            return self.dbconn['mimosa']
        except Exception as e:
            logging.error(f'Database error: {e}')
            return None

    def start_capture(self, target):
        t = threading.Thread(target=start_epc, args=(target,))
        self.epc_children[target['ip']] = (t, time.time())
        t.start()
        logging.debug(f'Started start_epc thread for {target["ip"]}')
        return t

    def stop_capture(self, target):
        t = threading.Thread(target=stop_epc, args=(target, self))
        self.epc_children[target['ip']] = (t, time.time())
        t.start()
        logging.debug(f'Started stop_epc thread for {target["ip"]}')
        return t

    def collect_capture(self, target):
        t = threading.Thread(target=collect_epc, args=(target, self))
        self.epc_children[target['ip']] = (t, time.time())
        t.start()
        logging.debug(f'Started collect_epc thread for {target["ip"]}')
        return t

    def fetch_file(self, url):
        t = threading.Thread(target=pop_ftp, args=(url, self))
        self.url_children[url] = (t, time.time())
        t.start()
        logging.debug(f'Started pop_ftp thread for {url}')
        return t

    def run(self):
        """Main daemon loop."""
        db = self.get_db()
        if not db:
            self.s.enter(10, 1, self.run)
            self.s.run()
            return

        # Process targets with 'RUNNING' capture
        targets = db['targets'].find({'capture': 'RUNNING'})
        for target in targets:
            if target['ip'] in self.epc_children and self.epc_children[target['ip']][0].is_alive():
                if time.time() - self.epc_children[target['ip']][1] < OP_TIMEOUT:
                    logging.debug(f'Operation running for target {target["ip"]}. Skipping.')
                    continue
                else:
                    logging.warning(f'Operation on target {target["ip"]} exceeded timeout.')

            if 'last_checked' not in target or (float(target['last_checked']) + float(target['interval'])) <= time.time():
                logging.info(f'Collecting capture for target {target["ip"]}.')
                self.collect_capture(target)
                db['targets'].update_one({'ip': target['ip']}, {'$set': {'last_checked': str(time.time())}})

        # Process targets with 'STOPPED' capture
        targets = db['targets'].find({'capture': 'STOPPED'})
        for target in targets:
            if target['ip'] in self.epc_children and self.epc_children[target['ip']][0].is_alive():
                if time.time() - self.epc_children[target['ip']][1] < OP_TIMEOUT:
                    logging.debug(f'Operation running for target {target["ip"]}. Skipping.')
                    continue
                else:
                    logging.warning(f'Operation on target {target["ip"]} exceeded timeout.')

            if 'last_checked' in target:
                logging.info(f'Stopping capture for target {target["ip"]}.')
                self.stop_capture(target)
                db['targets'].update_one({'ip': target['ip']}, {'$unset': {'last_checked': ''}})

        # Process file downloads
        with self.filelock:
            for url in list(self.files):
                if url in self.url_children and self.url_children[url][0].is_alive():
                    if time.time() - self.url_children[url][1] < OP_TIMEOUT:
                        logging.debug(f'Download in progress for {url}. Skipping.')
                        continue
                    else:
                        logging.warning(f'Download of {url} exceeded timeout.')

                logging.info(f'Starting download for {url}.')
                self.fetch_file(url)

        self.s.enter(10, 1, self.run)
        self.s.run()

def print_usage():
    print("Mimosa daemon.")
    print("Usage: sudo ./mimosad.py start|stop|restart")
    sys.exit(2)

if __name__ == '__main__':
    if os.geteuid() != 0:
        sys.exit("You need root privileges to run this script. Use 'sudo'.")

    if len(sys.argv) != 2 or sys.argv[1] not in COMMANDS:
        print_usage()

    mimosad = Mimosad(PIDFILE)
    if sys.argv[1] == 'start':
        logging.info('Starting MimosaD...')
        mimosad.start()
    elif sys.argv[1] == 'stop':
        logging.info('Stopping MimosaD...')
        mimosad.stop()
    elif sys.argv[1] == 'restart':
        logging.info('Restarting MimosaD...')
        mimosad.restart()
