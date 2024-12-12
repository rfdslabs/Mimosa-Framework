#!/usr/bin/python3
'''
***
Modified generic daemon class
***

Author:         http://www.jejik.com/articles/2007/02/
                        a_simple_unix_linux_daemon_in_python/www.boxedice.com

License:        http://creativecommons.org/licenses/by-sa/3.0/

Changes:        23rd Jan 2009 (David Mytton <david@boxedice.com>)
                - Replaced hard coded '/dev/null in __init__ with os.devnull
                - Added OS check to conditionally remove code that doesn't
                  work on OS X
                - Added output to console on completion
                - Tidied up formatting
                11th Mar 2009 (David Mytton <david@boxedice.com>)
                - Fixed problem with daemon exiting on Python 2.4
                  (before SystemExit was part of the Exception base)
                13th Aug 2010 (David Mytton <david@boxedice.com>
                - Fixed unhandled exception if PID file is empty



Updated Dec 11 / 2024
 Generic Daemon Class (Updated for Python 3) / (GPT / Claude)
'''

import os
import sys
import time
import signal
import atexit


class Daemon:
    """
    A generic daemon class.

    Usage: Subclass the Daemon class and override the run() method.
    """
    def __init__(self, pidfile, stdin=os.devnull, stdout=os.devnull, stderr=os.devnull, home_dir='.', umask=0o22, verbose=1):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile
        self.home_dir = home_dir
        self.verbose = verbose
        self.umask = umask
        self.daemon_alive = True

    def daemonize(self):
        """Daemonize the process using the UNIX double-fork mechanism."""
        try:
            pid = os.fork()
            if pid > 0:
                # Exit first parent
                sys.exit(0)
        except OSError as e:
            sys.stderr.write(f"Fork #1 failed: {e.errno} ({e.strerror})\n")
            sys.exit(1)

        # Decouple from parent environment
        os.chdir(self.home_dir)
        os.setsid()
        os.umask(self.umask)

        try:
            pid = os.fork()
            if pid > 0:
                # Exit from second parent
                sys.exit(0)
        except OSError as e:
            sys.stderr.write(f"Fork #2 failed: {e.errno} ({e.strerror})\n")
            sys.exit(1)

        # Redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        with open(self.stdin, 'r') as si, open(self.stdout, 'a+') as so, open(self.stderr, 'a+') as se:
            os.dup2(si.fileno(), sys.stdin.fileno())
            os.dup2(so.fileno(), sys.stdout.fileno())
            os.dup2(se.fileno(), sys.stderr.fileno())

        # Signal handlers
        signal.signal(signal.SIGTERM, self._sigterm_handler)
        signal.signal(signal.SIGINT, self._sigterm_handler)

        # Write PID file
        atexit.register(self.delpid)
        pid = str(os.getpid())
        with open(self.pidfile, 'w+') as f:
            f.write(f"{pid}\n")

        if self.verbose >= 1:
            print("Daemon started")

    def _sigterm_handler(self, signum, frame):
        """Handle termination signals."""
        self.daemon_alive = False

    def delpid(self):
        """Remove the PID file."""
        if os.path.exists(self.pidfile):
            os.remove(self.pidfile)

    def start(self, *args, **kwargs):
        """Start the daemon."""
        if self.verbose >= 1:
            print("Starting...")

        if self.get_pid():
            sys.stderr.write(f"PID file {self.pidfile} already exists. Is the daemon already running?\n")
            sys.exit(1)

        self.daemonize()
        self.run(*args, **kwargs)

    def stop(self):
        """Stop the daemon."""
        if self.verbose >= 1:
            print("Stopping...")

        pid = self.get_pid()
        if not pid:
            sys.stderr.write(f"PID file {self.pidfile} does not exist. Is the daemon not running?\n")
            return

        try:
            while True:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
        except OSError as e:
            if "No such process" in str(e):
                self.delpid()
            else:
                sys.stderr.write(f"Error stopping daemon: {e}\n")
                sys.exit(1)

        if self.verbose >= 1:
            print("Daemon stopped")

    def restart(self):
        """Restart the daemon."""
        self.stop()
        self.start()

    def get_pid(self):
        """Get the PID from the PID file."""
        try:
            with open(self.pidfile, 'r') as f:
                return int(f.read().strip())
        except (IOError, ValueError):
            return None

    def is_running(self):
        """Check if the daemon is running."""
        pid = self.get_pid()
        if pid and os.path.exists(f"/proc/{pid}"):
            print(f"Process (PID {pid}) is running...")
            return True
        print("Process is not running.")
        return False

    def run(self):
        """
        You should override this method when you subclass Daemon.
        It will be called after the process has been daemonized
        by start() or restart().
        """
        raise NotImplementedError
