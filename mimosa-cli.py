#!/usr/bin/python
#
# Mimosa v1.0a
# "Julio Auto"<julio@julioauto.com>
#
# This program was developed to use pymongo 2.2, which, although outdated, is
# the current version available for Debian/Kali, at time of writing.
#

from cmd2 import Cmd
from pymongo import Connection

DEFAULT_PASSWORD="cisco"
DEFAULT_INTERVAL="300"
NULL_FTP_STRING="<NONE>"
VALID_OPTIONS=['cisco_passwd','cap_interval','ftp_string']

class Mimosa(Cmd):
  dbconn = None
  prompt="Mimosa> " 

  def get_db(self):
    try:
      if self.dbconn == None:
        self.dbconn = Connection()
        
      self.dbconn.server_info()
      return self.dbconn['mimosa']
    except Exception, e:
      if e.__module__ == "pymongo.errors":
        self.dbconn = None
        print(self.colorize("Database error. Is MongoDB running?", "red")),
        
      print self.colorize("Cannot continue.", "red")
      return None


  def do_moo(self, arg):
    print self.colorize('Moo!', 'red')

  def do_list_targets(self, arg):
    """\
    List mimosa targets
    Usage: list_targets"""
    db = self.get_db()
    if db is None:
      return

    targets = db['targets'].find()
    if targets.count() == 0:
      print self.colorize("* No registered targets.", "bold")
      return

    print self.colorize("* IP Address\tCapture", 'bold')
    print self.colorize('--------------------------', 'bold')
    for target in targets:
      capture = self.colorize('STOPPED', 'red')
      if target['capture'] == 'RUNNING':
        capture = self.colorize('RUNNING', 'green')

      print (self.colorize("  %s" % target['ip'], 'bold')),
      print "\t[%s]" % capture

  def do_add_target(self, arg):
    """\
    Add a mimosa target
    Usage: add_target <IP Address> [Password] [FTP String]
    Examples: add_target 1.2.3.4
              add_target 2.2.2.2 ciscoadmin ftp://mimosa:mimosapasswd@3.3.3.3/mimosafolder
    If no password and/or FTP string is given, the default values will be used\
    (see mimosa_options)"""
    db = self.get_db()
    if db is None:
      return

    args = arg.split()
    if len(args) == 0:
      print self.colorize('* No arguments given.', 'red')
      return

    ip = args[0]
    password = None
    ftp_string = None
    if len(args) > 1:
      password = args[1]
      if len(args) > 2:
        ftp_string = args[2]

    if db['targets'].find_one({'ip' : ip}) is not None:
      print self.colorize('* Target already added! Please del_target\
 first!', 'red')
      return

    if password is None:
      def_password = db['options'].find_one({'name' : 'cisco_passwd'})
      if def_password is None:
        password = DEFAULT_PASSWORD
        db['options'].insert({'name' : 'cisco_passwd',
        'value' : DEFAULT_PASSWORD})
      else:
        password = def_password['value']

    if ftp_string is None:
      def_ftpstring = db['options'].find_one({'name' : 'ftp_string'})
      if def_ftpstring is None or def_ftpstring['value'] == NULL_FTP_STRING:
        db['options'].insert({'name' : 'ftp_string',
        'value' : NULL_FTP_STRING})
        print self.colorize('* Please inform FTP string or set a default FTP\
string (see mimosa_options)', 'red')
        return
      else:
        ftp_string = def_ftpstring['value']

    def_interval = db['options'].find_one({'name' : 'cap_interval'})
    if def_interval is None:
      interval = DEFAULT_INTERVAL
      db['options'].insert({'name' : 'cap_interval',
      'value' : DEFAULT_INTERVAL})
    else:
      interval = def_interval['value']

    db['targets'].insert({'ip' : ip, 'password' : password, 'ftp_string' :
    ftp_string, 'capture' : 'STOPPED', 'interval' : interval})
    print self.colorize('* OK!', 'bold')

  def do_del_target(self, arg):
    """\
    Delete a mimosa target
    Usage: del_target <IP Address>
    Examples: del_target 1.2.3.4"""
    db = self.get_db()
    if db is None:
      return

    args = arg.split()
    if len(args) == 0:
      print self.colorize('* No arguments given.', 'red')
      return

    ip = args[0]
    target = db['targets'].find_one({'ip' : ip})
    if target is None:
      print self.colorize('* No target found with this IP address. Nothing to \
do here.', 'bold')
      return

    if target['capture'] == 'RUNNING':
      print self.colorize('* You can not delete a running target! Please \
stop_capture first!', 'red')
      return
    
    db['targets'].remove(target['_id'])
    print self.colorize('* OK!', 'bold')

  def do_show_target(self, arg):
    """\
    Show more info on a mimosa target
    Usage: show_target <IP Address>
    Examples: show_target 1.2.3.4"""
    db = self.get_db()
    if db is None:
      return

    args = arg.split()
    if len(args) == 0:
      print self.colorize('* No arguments given.', 'red')
      return

    ip = args[0]
    target = db['targets'].find_one({'ip' : ip})
    if target is None:
      print self.colorize('* No target found with this IP address. Nothing to \
do here.', 'bold')
      return
    
    capture = self.colorize('STOPPED', 'red')
    if target['capture'] == 'RUNNING':
      capture = self.colorize('RUNNING', 'green')

    print self.colorize('* IP Address \t=>\t %s' % target['ip'], 'bold')
    print (self.colorize('* Capture job \t=>\t', 'bold')),
    print '[%s]' % capture
    print self.colorize('* Job interval \t=>\t %ss' % target['interval'], 'bold')
    print self.colorize('* Password \t=>\t %s' % target['password'], 'bold')
    print self.colorize('* FTP string \t=>\t %s' % target['ftp_string'], 'bold')

  def do_mimosa_options(self, arg):
    """\
    List or set Mimosa options
    Usage: mimosa_optons <list|set> [name] [value]
    Examples: mimosa_options list
              mimosa_options set ftp_string ftp://mimosa:mimosapassword@3.3.3.3/"""
    db = self.get_db()
    if db is None:
      return

    args = arg.split()
    if len(args) == 0:
      print self.colorize('* No arguments given.', 'red')
      return

    if args[0] == 'list':
      def_password = db['options'].find_one({'name' : 'cisco_passwd'})
      if def_password is None:
        password = DEFAULT_PASSWORD
        db['options'].insert({'name' : 'cisco_passwd',
        'value' : DEFAULT_PASSWORD})
      def_interval = db['options'].find_one({'name' : 'cap_interval'})
      if def_interval is None:
        interval = DEFAULT_INTERVAL
        db['options'].insert({'name' : 'cap_interval',
        'value' : DEFAULT_INTERVAL})
      def_ftpstring = db['options'].find_one({'name' : 'ftp_string'})
      if def_ftpstring is None:
        db['options'].insert({'name' : 'ftp_string',
        'value' : NULL_FTP_STRING})

      print self.colorize("* Name\t\tValue", 'bold')
      print self.colorize('--------------------------', 'bold')
      options = db['options'].find()
      for option in options:
        print self.colorize("  %s\t%s" % (option['name'], option['value']), 'bold')


    elif args[0] == 'set':
      if len(args) < 3:
        print self.colorize('* Insufficient arguments.', 'red')
        return
      elif args[1] not in VALID_OPTIONS:
        print self.colorize('* Invalid option name.', 'red')
        return

      db['options'].update({'name' : args[1]}, {'$set' : {'value' : args[2]}})
      print self.colorize('* OK!', 'bold')

    else:
      print self.colorize('* Invalid command.', 'red')
      return

  def do_start_capture(self, arg):
    """\
    Start the capture job on a Mimosa target
    Usage: start_capture <IP Address>
    Examples: start_capture 1.2.3.4"""
    db = self.get_db()
    if db is None:
      return

    args = arg.split()
    if len(args) == 0:
      print self.colorize('* No arguments given.', 'red')
      return

    ip = args[0]
    target = db['targets'].find_one({'ip' : ip})
    if target is None:
      print self.colorize('* No target found with this IP address. Nothing to \
do here.', 'bold')
      return
    
    if target['capture'] == 'RUNNING':
      print self.colorize('* Capture job already started for this target. Nothing to \
do here.', 'bold')
      return

    db['targets'].update({'ip' : target['ip']}, {'$set' : {'capture' : 'RUNNING'}})

  def do_stop_capture(self, arg):
    """\
    Stop the capture job on a Mimosa target
    Usage: stop_capture <IP Address>
    Examples: stop_capture 1.2.3.4"""
    db = self.get_db()
    if db is None:
      return

    args = arg.split()
    if len(args) == 0:
      print self.colorize('* No arguments given.', 'red')
      return

    ip = args[0]
    target = db['targets'].find_one({'ip' : ip})
    if target is None:
      print self.colorize('* No target found with this IP address. Nothing to \
do here.', 'bold')
      return
    
    if target['capture'] == 'STOPPED':
      print self.colorize('* Capture job already stopped for this target. Nothing to \
do here.', 'bold')
      return

    db['targets'].update({'ip' : target['ip']}, {'$set' : {'capture' : 'STOPPED'}})

  

mimosa = Mimosa()
mimosa.cmdloop()
