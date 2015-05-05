import pexpect, logging, sys, time

def start_epc(target):
  try:
    tel = pexpect.spawn('telnet %s' % target['ip'])
    tel.logfile = sys.stdout
    tel.expect('Password: ')
    tel.sendline(target['password'])
    tel.sendline('term length 0')
    tel.sendline('en')
    tel.expect('Password: ')
    tel.sendline(target['password'])
    ena = tel.expect('#')
    if ena == 0:
      logging.debug('Starting EPC Sniffer ... => %s' % target['ip'])
      tel.sendline('monitor capture buffer pkt-test-f2 size 5120 max-size 2048 linear')
      tel.sendline('monitor capture point ip cef point-test-f2 all both')
      tel.sendline('monitor capture point associate point-test-f2 pkt-test-f2')
      tel.sendline('monitor capture point start point-test-f2')
      tel.sendline('exit')
      tel.expect(pexpect.EOF, timeout=None)
    else:
      logging.warning('Enable mode for %s [FAIL]' % target['ip'])

  except Exception, e:
    logging.debug(e)
    logging.error("Error while starting capture for %s" % target['ip'])

def stop_epc(target, mimosad):
  try:
    tel = pexpect.spawn('telnet %s' % target['ip'])
    tel.logfile = sys.stdout
    tel.expect('Password: ')
    tel.sendline(target['password'])
    tel.sendline('term length 0')
    tel.sendline('en')
    tel.expect('Password: ')
    tel.sendline(target['password'])
    ena = tel.expect('#')
    if ena == 0:
      logging.debug('Stopping EPC Sniffer ... => %s' % target['ip'])
      tel.sendline('monitor capture point stop point-test-f2')
      file_url = '%s/%s_%s.pcap' % (target['ftp_string'], target['ip'], str(time.time()))
      tel.sendline('monitor capture buffer pkt-test-f2 export %s' % file_url)
      # TODO: find a decent way to replace the sleep below
      # In fact, what's the effect of not having the sleep() at all?
      time.sleep(20)
      tel.sendline('exit')
      tel.expect(pexpect.EOF, timeout=None)

      with mimosad.filelock:
        mimosad.files.append(file_url)

    else:
      logging.warning('Enable mode for %s [FAIL]' % target['ip'])

  except Exception, e:
    logging.debug(e)
    logging.error("Error while stopping capture for %s" % target['ip'])

def collect_epc(target, mimosad):
  stop_epc(target, mimosad)
  start_epc(target)
