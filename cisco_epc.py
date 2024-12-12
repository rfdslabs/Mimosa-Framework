import pexpect
import logging
import sys
import time
from threading import Lock

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class MimosaDaemon:
    def __init__(self):
        self.filelock = Lock()
        self.files = []

def connect_to_device(target):
    """
    Connect to a device via telnet.
    """
    try:
        tel = pexpect.spawn(f'telnet {target["ip"]}', timeout=10)
        tel.logfile = sys.stdout
        tel.expect('Password: ')
        tel.sendline(target['password'])
        tel.sendline('term length 0')
        tel.sendline('en')
        tel.expect('Password: ')
        tel.sendline(target['password'])
        index = tel.expect(['#', pexpect.TIMEOUT, pexpect.EOF])
        if index == 0:
            logging.debug(f'Connected to {target["ip"]} in enable mode.')
            return tel
        else:
            logging.warning(f'Failed to enter enable mode for {target["ip"]}.')
            tel.close()
            return None
    except pexpect.ExceptionPexpect as e:
        logging.error(f'Error connecting to device {target["ip"]}: {str(e)}')
        return None

def start_epc(target):
    """
    Start EPC sniffer on the target device.
    """
    logging.debug(f'Starting EPC Sniffer for {target["ip"]}...')
    tel = connect_to_device(target)
    if not tel:
        return

    try:
        tel.sendline('monitor capture buffer pkt-test-f2 size 5120 max-size 2048 linear')
        tel.sendline('monitor capture point ip cef point-test-f2 all both')
        tel.sendline('monitor capture point associate point-test-f2 pkt-test-f2')
        tel.sendline('monitor capture point start point-test-f2')
        tel.sendline('exit')
        tel.expect(pexpect.EOF, timeout=10)
        logging.debug(f'EPC Sniffer started successfully for {target["ip"]}.')
    except pexpect.ExceptionPexpect as e:
        logging.error(f'Error while starting EPC Sniffer for {target["ip"]}: {str(e)}')
    finally:
        tel.close()

def stop_epc(target, mimosad):
    """
    Stop EPC sniffer on the target device and export the capture file.
    """
    logging.debug(f'Stopping EPC Sniffer for {target["ip"]}...')
    tel = connect_to_device(target)
    if not tel:
        return

    try:
        tel.sendline('monitor capture point stop point-test-f2')
        file_url = f'{target["ftp_string"]}/{target["ip"]}_{int(time.time())}.pcap'
        tel.sendline(f'monitor capture buffer pkt-test-f2 export {file_url}')
        logging.debug(f'Exporting capture to {file_url}...')
        time.sleep(20)  # Sleep to allow export to complete
        tel.sendline('exit')
        tel.expect(pexpect.EOF, timeout=10)

        with mimosad.filelock:
            mimosad.files.append(file_url)
            logging.debug(f'Capture file added to list: {file_url}')
    except pexpect.ExceptionPexpect as e:
        logging.error(f'Error while stopping EPC Sniffer for {target["ip"]}: {str(e)}')
    finally:
        tel.close()

def collect_epc(target, mimosad):
    """
    Collect EPC capture by stopping and restarting the sniffer.
    """
    stop_epc(target, mimosad)
    start_epc(target)

# Example usage
if __name__ == '__main__':
    target_device = {
        "ip": "192.168.1.1",
        "password": "cisco",
        "ftp_string": "ftp://user:pass@192.168.1.2/export"
    }
    mimosa_daemon = MimosaDaemon()

    # Start capture
    start_epc(target_device)

    # Stop and collect
    collect_epc(target_device, mimosa_daemon)

    # View exported files
    logging.info(f"Exported files: {mimosa_daemon.files}")
