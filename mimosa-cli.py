#!/usr/bin/python3
## Mimosa v1.0a
# "Julio Auto"<julio@julioauto.com>
#
# This program was developed to use pymongo 2.2, which, although outdated, is
# the current version available for Debian/Kali, at time of writing.
#
# Mimosa v2.0
# Modernized version of the original script (GPT/Claude)
#

import pymongo
from pymongo import MongoClient
from cmd import Cmd

DEFAULT_PASSWORD = "cisco"
DEFAULT_INTERVAL = "300"
NULL_FTP_STRING = "<NONE>"
VALID_OPTIONS = ['cisco_passwd', 'cap_interval', 'ftp_string']

class Mimosa(Cmd):
    prompt = "Mimosa> "
    dbconn = None

    def get_db(self):
        """Establish and return a MongoDB connection."""
        if not self.dbconn:
            try:
                self.dbconn = MongoClient()
                # Verify connection
                self.dbconn.admin.command('ping')
            except pymongo.errors.ConnectionFailure:
                print("Error: Unable to connect to MongoDB. Is it running?")
                return None
        return self.dbconn['mimosa']

    def do_list_targets(self, arg):
        """List all Mimosa targets."""
        db = self.get_db()
        if not db:
            return

        targets = db['targets'].find()
        if targets.count() == 0:
            print("* No registered targets.")
            return

        print("* IP Address\tCapture Status")
        print("----------------------------")
        for target in targets:
            capture = "RUNNING" if target.get('capture') == "RUNNING" else "STOPPED"
            print(f"{target['ip']}\t[{capture}]")

    def do_add_target(self, arg):
        """Add a new target to Mimosa."""
        db = self.get_db()
        if not db:
            return

        args = arg.split()
        if not args:
            print("Usage: add_target <IP> [Password] [FTP String]")
            return

        ip = args[0]
        password = args[1] if len(args) > 1 else DEFAULT_PASSWORD
        ftp_string = args[2] if len(args) > 2 else NULL_FTP_STRING

        if db['targets'].find_one({'ip': ip}):
            print(f"Error: Target {ip} already exists. Please delete it first.")
            return

        db['targets'].insert_one({
            'ip': ip,
            'password': password,
            'ftp_string': ftp_string,
            'capture': 'STOPPED',
            'interval': DEFAULT_INTERVAL
        })
        print(f"Target {ip} added successfully.")

    def do_del_target(self, arg):
        """Delete a Mimosa target."""
        db = self.get_db()
        if not db:
            return

        if not arg:
            print("Usage: del_target <IP>")
            return

        result = db['targets'].delete_one({'ip': arg.strip()})
        if result.deleted_count:
            print(f"Target {arg} deleted successfully.")
        else:
            print(f"Error: Target {arg} not found.")

    def do_show_target(self, arg):
        """Show details of a specific target."""
        db = self.get_db()
        if not db:
            return

        if not arg:
            print("Usage: show_target <IP>")
            return

        target = db['targets'].find_one({'ip': arg.strip()})
        if not target:
            print(f"Error: No target found with IP {arg.strip()}.")
            return

        print(f"IP Address: {target['ip']}")
        print(f"Capture Status: {target['capture']}")
        print(f"Interval: {target['interval']}s")
        print(f"Password: {target['password']}")
        print(f"FTP String: {target['ftp_string']}")

    def do_start_capture(self, arg):
        """Start capture on a target."""
        db = self.get_db()
        if not db:
            return

        if not arg:
            print("Usage: start_capture <IP>")
            return

        target = db['targets'].find_one({'ip': arg.strip()})
        if not target:
            print(f"Error: Target {arg.strip()} not found.")
            return

        if target['capture'] == 'RUNNING':
            print(f"Capture already running for {arg.strip()}.")
            return

        db['targets'].update_one({'ip': arg.strip()}, {'$set': {'capture': 'RUNNING'}})
        print(f"Capture started for {arg.strip()}.")

    def do_stop_capture(self, arg):
        """Stop capture on a target."""
        db = self.get_db()
        if not db:
            return

        if not arg:
            print("Usage: stop_capture <IP>")
            return

        target = db['targets'].find_one({'ip': arg.strip()})
        if not target:
            print(f"Error: Target {arg.strip()} not found.")
            return

        if target['capture'] == 'STOPPED':
            print(f"Capture already stopped for {arg.strip()}.")
            return

        db['targets'].update_one({'ip': arg.strip()}, {'$set': {'capture': 'STOPPED'}})
        print(f"Capture stopped for {arg.strip()}.")

    def do_exit(self, arg):
        """Exit the application."""
        print("Exiting Mimosa. Goodbye!")
        return True


if __name__ == "__main__":
    Mimosa().cmdloop()
