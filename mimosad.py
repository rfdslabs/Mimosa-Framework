#!/usr/bin/python
#
# Mimosa v1.0a
# "Julio Auto"<julio@julioauto.com>
#
# This program was developed to use pymongo 2.2, which, although outdated, is
# the current version available for Debian/Kali, at time of writing.
#

from daemon import Daemon
from pymongo import Connection
import sched, time, sys, os, logging, threading, urllib, tempfile
from cisco_epc import start_epc, stop_epc, collect_epc

PIDFILE = '/var/run/mimosad.pid'
LOGFILE = '/var/log/mimosad.log'
LOGLEVEL = logging.DEBUG
OP_TIMEOUT = 120
DL_DIR = '/tmp'
DL_THRESHOLD = 50 # "Maximum" (not really) number of concurrent downloads
COMMANDS = ['start', 'stop', 'restart']

def pop_ftp(url, mimosad):
  # Removing the url right here means it will not be retried if anything below
  # goes wrong. Proper error handling would encompass retrying too.
  with mimosad.filelock:
    mimosad.files.pop(mimosad.files.index(url))

  # TODO: replace this code with something that gets from FTP and then
  # _removes_ the file from the FTP (i.e. a real pop()). ftplib and urlparse
  # are good starting points...
  tmp = tempfile.mkstemp(dir=DL_DIR)
  os.close(tmp[0])

  urllib.urlretrieve(url, tmp[1])

  logging.info('%s downloaded to %s' % (url, tmp[1]))

class Mimosad(Daemon):
  s = None
  dbconn = None
  epc_children = dict()
  url_children = dict()
  files = []
  filelock = threading.RLock()

  def __init__(self, pidfile):
    try:
      self.dbconn = Connection()
      self.s = sched.scheduler(time.time, time.sleep)
      logging.basicConfig(format='[%(asctime)s][%(levelname)s] %(message)s', filename=LOGFILE,level=LOGLEVEL)
    except Exception, e:
      logging.debug(e)
      if e.__module__ == "pymongo.errors":
        self.dbconn = None
        logging.error("Database error. Is MongoDB running? Cannot continue.")
      else:        
        logging.error("Unknown error at startup. Cannot continue.")

      sys.exit()

    super(Mimosad, self).__init__(pidfile)

  def get_db(self):
    try:
      if self.dbconn == None:
        self.dbconn = Connection()
        
      self.dbconn.server_info()
      return self.dbconn['mimosa']
    except Exception, e:
      logging.debug(e)
      if e.__module__ == "pymongo.errors":
        self.dbconn = None
        logging.error("Database error. Is MongoDB running? Looping...")
      else:        
        logging.error("Unknown error at get_db(). Looping...")

      return None

  def start_capture(self, target):
    t = threading.Thread(target=start_epc, args=(target,))
    self.epc_children[target['ip']]=(t, time.time())
    t.start()
    logging.debug('Started start_epc thread for %s' % target['ip'])
    return t

  def stop_capture(self, target):
    t = threading.Thread(target=stop_epc, args=(target,self,))
    self.epc_children[target['ip']]=(t, time.time())
    t.start()
    logging.debug('Started stop_epc thread for %s' % target['ip'])
    return t

  def collect_capture(self, target):
    t = threading.Thread(target=collect_epc, args=(target,self,))
    self.epc_children[target['ip']]=(t, time.time())
    t.start()
    logging.debug('Started collect_epc thread for %s' % target['ip'])
    return t

  def fetch_file(self, url):
    t = threading.Thread(target=pop_ftp, args=(url,self,))
    self.url_children[url]=(t, time.time())
    t.start()
    logging.debug('Started pop_ftp thread for %s' % url)
    return t

  def run(self):
    db = self.get_db()
    if db is None:
      self.s.enter(10, 1, Mimosad.run, (self,))
      self.s.run()
      return

    targets = db['targets'].find({'capture' : 'RUNNING'})
    for target in targets:
      if target['ip'] in self.epc_children:
        if self.epc_children[target['ip']][0].isAlive():
          if time.time() - self.epc_children[target['ip']][1] < OP_TIMEOUT:
            logging.debug('Operation running for target %s. Will check back \
later.' % target['ip'])
            continue
          else:
            logging.warning('Operation on target %s exceeded timeout value. \
Can not do anything but override this and move on.' %
            target['ip'])

      if 'last_checked' not in target:
        # First timer
        logging.info('Starting target %s...' % target['ip'])
        self.start_capture(target)
        db['targets'].update({'ip' : target['ip']}, {'$set' : {'last_checked'
        : str(time.time())}})
        
      elif (float(target['last_checked']) + float(target['interval'])) <= time.time():
        # Time to collect
        logging.info('Checking target %s...' % target['ip'])
        self.collect_capture(target)
        db['targets'].update({'ip' : target['ip']}, {'$set' : {'last_checked'
        : str(time.time())}})


    targets = db['targets'].find({'capture' : 'STOPPED'})
    for target in targets:
      if target['ip'] in self.epc_children:
        if self.epc_children[target['ip']][0].isAlive():
          if (time.time() - self.epc_children[target['ip']][1]) < OP_TIMEOUT:
            logging.debug('Operation running for target %s. Will check back \
later.' % target['ip'])
            continue
          else:
            logging.warning('Operation on target %s exceeded timeout value. \
Can not do anything but override this and move on.' %
            target['ip'])

      if 'last_checked' in target:
        # Changed status. Must be stopped
        logging.info('Stopping target %s...' % target['ip'])
        self.stop_capture(target)
        db['targets'].update({'ip' : target['ip']}, {'$unset' : {'last_checked'
        : ''}})

    # Download the caps
    with self.filelock:
      if len(self.files) > DL_THRESHOLD:
        self.warning('Looks like you have %d simultaneous downloads. Wow!(?)' %
        len(self.files))

      for url in self.files:
        if url in self.url_children:
          if self.url_children[url][0].isAlive():
            if (time.time() - self.url_children[url][1]) < OP_TIMEOUT:
              logging.debug('Download of %s already in progress. Will check \
back later.' % url)
              continue
            else:
              logging.warning('Download of  %s exceeded timeout value. \
Can not do anything but override this and move on.' %
              url)

        logging.info('Starting download of %s...' % url)
        self.fetch_file(url)

    self.s.enter(10, 1, Mimosad.run, (self,))
    self.s.run()



def print_usage():
  print 'Mimosa daemon.'
  print 'TL;DR Usage: sudo ./mimosad.py start'
  sys.exit()

if os.geteuid() != 0:
  exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

if len(sys.argv) != 2 or (sys.argv[1] not in COMMANDS):
  print_usage()

mimosad = Mimosad(PIDFILE)
if sys.argv[1] == 'start':
  logging.info('Starting MimosaD...')
  mimosad.start()
  #mimosad.run()
elif sys.argv[1] == 'stop':
  logging.info('Stopping MimosaD...')
  mimosad.stop()
elif sys.argv[1] == 'restart':
  logging.info('Restarting MimosaD...')
  mimosad.restart()
