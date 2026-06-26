"""
pwnagotchi_sync.py - Sync WPA handshakes from a separate Pwnagotchi device
and attempt to crack them with aircrack-ng or hashcat.

Cracked WiFi credentials are stored to shared_data.wififile (wifi.csv).
Handshake files are downloaded to /root/handshakes/ so the Ragnar webapp's
existing discovery view picks them up automatically.
"""

import os
import re
import csv
import glob
import time
import shutil
import logging
import subprocess
import tempfile

import paramiko

from logger import Logger

logger = Logger(name="pwnagotchi_sync", level=logging.DEBUG)

b_class = "PwnagotchiSync"
b_module = "pwnagotchi_sync"
b_status = "pwnagotchi_sync"
b_port = None
b_parent = None

LOCAL_HANDSHAKE_DIR = "/root/handshakes"
SYNC_COOLDOWN = 3600  # seconds between syncs

_last_sync_time = 0  # module-level throttle so execute() is a no-op on repeat calls


class PwnagotchiSync:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        logger.info("PwnagotchiSync initialized")

    def execute(self, ip, port, row, status_key):
        global _last_sync_time

        cfg = self.shared_data.config
        if not cfg.get("pwnagotchi_peer_enabled", False):
            return "success"

        now = time.time()
        if now - _last_sync_time < SYNC_COOLDOWN:
            return "success"

        peer_ip = cfg.get("pwnagotchi_peer_ip", "").strip()
        if not peer_ip:
            logger.warning("PwnagotchiSync: pwnagotchi_peer_ip not configured")
            return "success"

        _last_sync_time = now
        self.shared_data.ragnarorch_status = "PwnagotchiSync"

        try:
            syncer = _Syncer(self.shared_data)
            syncer.run()
        except Exception as exc:
            logger.error(f"PwnagotchiSync failed: {exc}")

        return "success"


class _Syncer:
    HANDSHAKE_EXTS = (".pcap", ".pcapng", ".22000", ".hc22000")

    def __init__(self, shared_data):
        cfg = shared_data.config
        self.peer_ip = cfg.get("pwnagotchi_peer_ip", "").strip()
        self.ssh_user = cfg.get("pwnagotchi_peer_ssh_user", "root")
        self.ssh_password = cfg.get("pwnagotchi_peer_ssh_password", "")
        self.ssh_key = cfg.get("pwnagotchi_peer_ssh_key", "")
        self.remote_dir = cfg.get("pwnagotchi_peer_handshake_dir", "/root/handshakes")
        self.wordlist = shared_data.passwordsfile
        self.wififile = shared_data.wififile

        os.makedirs(LOCAL_HANDSHAKE_DIR, exist_ok=True)
        self._ensure_wififile()

    def _ensure_wififile(self):
        if not os.path.exists(self.wififile):
            os.makedirs(os.path.dirname(self.wififile), exist_ok=True)
            with open(self.wififile, "w", newline="") as f:
                csv.writer(f).writerow(["SSID", "BSSID", "Password", "Source"])

    def _connect_ssh(self):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = dict(
            hostname=self.peer_ip,
            username=self.ssh_user,
            timeout=30,
            look_for_keys=False,
            allow_agent=False,
        )
        if self.ssh_key and os.path.exists(self.ssh_key):
            kwargs["key_filename"] = self.ssh_key
        elif self.ssh_password:
            kwargs["password"] = self.ssh_password
        else:
            # Fall back to agent / default key locations
            kwargs["look_for_keys"] = True
            kwargs["allow_agent"] = True
        ssh.connect(**kwargs)
        return ssh

    def run(self):
        logger.info(f"Connecting to Pwnagotchi peer {self.peer_ip}")
        try:
            ssh = self._connect_ssh()
        except Exception as exc:
            logger.error(f"SSH to Pwnagotchi peer failed: {exc}")
            return

        try:
            new_files = self._download_new(ssh)
        finally:
            ssh.close()

        logger.info(f"Downloaded {len(new_files)} new handshake file(s)")

        cracked = 0
        for fpath in new_files:
            result = self._crack(fpath)
            if result:
                self._save(*result, source=os.path.basename(fpath))
                cracked += 1

        cracked += self._retry_existing(exclude=set(new_files))

        if cracked:
            logger.success(f"Cracked {cracked} WiFi network(s) from Pwnagotchi sync")
        else:
            logger.info("Pwnagotchi sync complete — no new credentials cracked")

    # ------------------------------------------------------------------ #
    #  File download
    # ------------------------------------------------------------------ #

    def _download_new(self, ssh):
        sftp = ssh.open_sftp()
        new_files = []
        try:
            remote_entries = sftp.listdir(self.remote_dir)
        except Exception as exc:
            logger.warning(f"Cannot list {self.remote_dir} on peer: {exc}")
            sftp.close()
            return new_files

        for fname in remote_entries:
            if not any(fname.lower().endswith(ext) for ext in self.HANDSHAKE_EXTS):
                continue
            local_path = os.path.join(LOCAL_HANDSHAKE_DIR, fname)
            remote_path = f"{self.remote_dir}/{fname}"
            try:
                rstat = sftp.stat(remote_path)
                if os.path.exists(local_path) and os.path.getsize(local_path) == rstat.st_size:
                    continue  # already have this file
                sftp.get(remote_path, local_path)
                new_files.append(local_path)
                logger.info(f"Downloaded handshake: {fname}")
            except Exception as exc:
                logger.warning(f"Download failed for {fname}: {exc}")

        sftp.close()
        return new_files

    # ------------------------------------------------------------------ #
    #  Cracking
    # ------------------------------------------------------------------ #

    def _crack(self, fpath):
        low = fpath.lower()
        if low.endswith(".22000") or low.endswith(".hc22000"):
            return self._crack_hashcat(fpath)
        return self._crack_aircrack(fpath)

    def _crack_aircrack(self, pcap_path):
        if not shutil.which("aircrack-ng"):
            logger.debug("aircrack-ng not found; install with: apt-get install aircrack-ng")
            return None

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            out_file = tmp.name

        try:
            proc = subprocess.run(
                ["aircrack-ng", "-w", self.wordlist, "-l", out_file, pcap_path],
                capture_output=True, text=True, timeout=300,
            )
            if os.path.exists(out_file):
                password = open(out_file).read().strip()
                if password:
                    ssid, bssid = self._parse_filename(pcap_path)
                    ssid = ssid or self._extract_ssid(proc.stdout)
                    bssid = bssid or self._extract_bssid(proc.stdout)
                    return ssid or "Unknown", bssid or "Unknown", password
        except subprocess.TimeoutExpired:
            logger.warning(f"aircrack-ng timed out on {os.path.basename(pcap_path)}")
        except Exception as exc:
            logger.error(f"aircrack-ng error: {exc}")
        finally:
            if os.path.exists(out_file):
                os.unlink(out_file)
        return None

    def _crack_hashcat(self, h22000_path):
        if not shutil.which("hashcat"):
            logger.debug("hashcat not found; skipping .22000 crack")
            return None

        potfile = h22000_path + ".pot"
        try:
            subprocess.run(
                ["hashcat", "-m", "22000", "--potfile-path", potfile,
                 "--quiet", h22000_path, self.wordlist],
                capture_output=True, text=True, timeout=600,
            )
            if os.path.exists(potfile):
                for line in open(potfile):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # potfile format: hash:password
                    password = line.rsplit(":", 1)[-1] if ":" in line else None
                    if password:
                        ssid, bssid = self._parse_filename(h22000_path)
                        return ssid or "Unknown", bssid or "Unknown", password
        except subprocess.TimeoutExpired:
            logger.warning(f"hashcat timed out on {os.path.basename(h22000_path)}")
        except Exception as exc:
            logger.error(f"hashcat error: {exc}")
        return None

    # ------------------------------------------------------------------ #
    #  Filename parsing — mirrors webapp's _parse_pwnagotchi_filename()
    # ------------------------------------------------------------------ #

    def _parse_filename(self, fpath):
        name = os.path.basename(fpath)
        for ext in (".hc22000", ".pcapng", ".22000", ".pcap"):
            if name.lower().endswith(ext):
                name = name[:-len(ext)]
                break

        # BSSID with colons
        m = re.search(r"_([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})$", name)
        if m:
            return name[: m.start()] or None, m.group(1).lower()

        # BSSID as 12 contiguous hex chars
        m = re.search(r"_([0-9a-fA-F]{12})$", name)
        if m:
            raw = m.group(1).lower()
            bssid = ":".join(raw[i: i + 2] for i in range(0, 12, 2))
            return name[: m.start()] or None, bssid

        # BSSID with underscores
        m = re.search(
            r"_([0-9a-fA-F]{2})_([0-9a-fA-F]{2})_([0-9a-fA-F]{2})"
            r"_([0-9a-fA-F]{2})_([0-9a-fA-F]{2})_([0-9a-fA-F]{2})$",
            name,
        )
        if m:
            bssid = ":".join(m.group(i).lower() for i in range(1, 7))
            return name[: m.start()] or None, bssid

        return name, None

    def _extract_ssid(self, stdout):
        m = re.search(r"ESSID.*?[\"'](.+?)[\"']", stdout)
        return m.group(1) if m else None

    def _extract_bssid(self, stdout):
        m = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", stdout)
        return m.group(1).lower() if m else None

    # ------------------------------------------------------------------ #
    #  Credential storage
    # ------------------------------------------------------------------ #

    def _already_cracked(self, source):
        if not os.path.exists(self.wififile):
            return False
        try:
            with open(self.wififile, newline="") as f:
                return any(row.get("Source") == source for row in csv.DictReader(f))
        except Exception:
            return False

    def _save(self, ssid, bssid, password, source):
        if self._already_cracked(source):
            return
        with open(self.wififile, "a", newline="") as f:
            csv.writer(f).writerow([ssid, bssid, password, source])
        logger.success(f"WiFi cracked — SSID: {ssid}  BSSID: {bssid}  Password: {password}")

    def _retry_existing(self, exclude):
        cracked = 0
        try:
            for fpath in glob.glob(os.path.join(LOCAL_HANDSHAKE_DIR, "*")):
                if fpath in exclude:
                    continue
                if not any(fpath.lower().endswith(ext) for ext in self.HANDSHAKE_EXTS):
                    continue
                if self._already_cracked(os.path.basename(fpath)):
                    continue
                result = self._crack(fpath)
                if result:
                    self._save(*result, source=os.path.basename(fpath))
                    cracked += 1
        except Exception as exc:
            logger.warning(f"Retry existing error: {exc}")
        return cracked
