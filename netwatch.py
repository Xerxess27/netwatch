#!/usr/bin/env python3
"""NetWatch: a home network watchdog.

Finds every device on your network, guesses what each one is, alerts you
(Telegram + desktop) when an unknown device joins, flags risky open ports,
and detects ARP-spoofing / man-in-the-middle attacks. Comes with a live web
dashboard.

Only run it on networks you own or are allowed to monitor.

Quick start:
    sudo python3 netwatch.py monitor        # watch + dashboard on http://127.0.0.1:8080
    python3 netwatch.py demo                # try the dashboard with a simulated network
"""
from __future__ import annotations

import argparse
import fcntl
import getpass
import html
import importlib.util
import ipaddress
import json
import os
import pwd
import re
import secrets
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

VERSION = "1.0.0"

PROBE_REFRESH = 6 * 3600          # re-check a device's open ports every 6h
EVENT_RETENTION = 30 * 86400      # keep 30 days of events
BAD_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}
TOKEN_RE = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{30,}$")

# port -> (service, risk note or None). These are the ports we probe.
PORTS = {
    21: ("FTP", "Unencrypted file transfer, so passwords travel in plain text"),
    22: ("SSH", None),
    23: ("Telnet", "Unencrypted remote login, a favourite target of IoT botnets like Mirai"),
    53: ("DNS", None),
    80: ("HTTP", None),
    139: ("NetBIOS", None),
    443: ("HTTPS", None),
    445: ("SMB", None),
    554: ("RTSP", "Camera video stream: make sure it requires a password"),
    631: ("IPP", None),
    1883: ("MQTT", "Unencrypted IoT messaging, often with no password"),
    2323: ("Telnet-alt", "Alternate Telnet port, commonly abused by IoT malware"),
    3389: ("RDP", "Remote Desktop: make sure it has a strong password"),
    5000: ("UPnP/NAS", None),
    5900: ("VNC", "Remote desktop that is often weakly protected"),
    8008: ("Cast", None),
    8009: ("Cast", None),
    8080: ("HTTP-alt", None),
    8443: ("HTTPS-alt", None),
    9100: ("Printer", None),
    9999: ("Kasa", None),
    62078: ("Apple-sync", None),
}

VM_PREFIXES = {
    "08:00:27": "VirtualBox", "0a:00:27": "VirtualBox", "00:0c:29": "VMware",
    "00:50:56": "VMware", "00:05:69": "VMware", "52:54:00": "QEMU/KVM",
    "00:15:5d": "Hyper-V", "00:1c:42": "Parallels",
}

# --------------------------------------------------------------------------- terminal output

class Color:
    enabled = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if Color.enabled else s


def green(s): return _c("32", s)
def red(s): return _c("1;31", s)
def yellow(s): return _c("33", s)
def cyan(s): return _c("36", s)
def dim(s): return _c("2", s)
def bold(s): return _c("1", s)


def fit(text, width: int) -> str:
    text = str(text if text is not None else "")
    return text[: width - 1] + "…" if len(text) > width else text.ljust(width)


def die(msg: str, code: int = 1):
    print(red("error: ") + msg, file=sys.stderr)
    sys.exit(code)


# --------------------------------------------------------------------------- helpers

def norm_mac(value: str | None) -> str | None:
    if not value or not re.fullmatch(r"[0-9A-Fa-f:.\-]{12,17}", value.strip()):
        return None
    h = re.sub(r"[^0-9a-f]", "", value.lower())
    if len(h) != 12:
        return None
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def is_private_mac(mac: str) -> bool:
    """Locally-administered bit set: phones/laptops use these 'random' MACs for privacy."""
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except (ValueError, TypeError):
        return False


def ip_key(ip: str):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0


def clean_hostname(name: str | None, ip: str = "") -> str:
    """Reverse-DNS names are attacker-controlled: keep only safe characters."""
    if not name:
        return ""
    name = re.sub(r"[^A-Za-z0-9._-]", "", name.strip().rstrip("."))[:63]
    if not name or name == ip or name.endswith("in-addr.arpa"):
        return ""
    for suffix in (".localdomain", ".home.arpa", ".lan", ".local", ".home", ".router", ".domain"):
        if name.lower().endswith(suffix) and len(name) > len(suffix):
            name = name[: -len(suffix)]
            break
    return name


def clean_label(name: str) -> str:
    name = "".join(ch for ch in name if ch.isprintable()).strip()
    return name[:40]


def port_name(p: int) -> str:
    return f"{PORTS[p][0]} {p}" if p in PORTS else str(p)


def risky(ports) -> list[int]:
    return [p for p in (ports or []) if PORTS.get(p, ("", None))[1]]


# --------------------------------------------------------------------------- storage paths

class Paths:
    """Under sudo, keep data in the invoking user's home so `sudo` and non-sudo runs share it."""

    def __init__(self, override: str | None = None):
        home, self.owner = os.path.expanduser("~"), None
        user = os.environ.get("SUDO_USER")
        if os.geteuid() == 0 and user and user != "root":
            try:
                pw = pwd.getpwnam(user)
                home, self.owner = pw.pw_dir, (pw.pw_uid, pw.pw_gid)
            except KeyError:
                pass
        self.home = home
        self.dir = os.path.abspath(override or os.environ.get("NETWATCH_DIR") or os.path.join(home, ".config", "netwatch"))
        if self.owner and not self.dir.startswith(os.path.abspath(home) + os.sep):
            self.owner = None  # e.g. /var/lib/netwatch for a system service stays root-owned
        self.db = os.path.join(self.dir, "netwatch.db")
        self.config = os.path.join(self.dir, "config.json")

    def ensure(self):
        missing, d = [], self.dir
        while d and not os.path.exists(d):
            missing.append(d)
            d = os.path.dirname(d)
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        for m in missing:
            self.fix(m)

    def fix(self, path: str):
        if self.owner and os.path.exists(path):
            try:
                os.chown(path, *self.owner)
            except OSError:
                pass


def load_config(paths: Paths, env: bool = True) -> dict:
    cfg: dict = {}
    try:
        with open(paths.config, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        pass
    if not isinstance(cfg, dict):
        cfg = {}
    if env:
        tg = dict(cfg.get("telegram") or {})
        if os.environ.get("NETWATCH_TELEGRAM_TOKEN"):
            tg["token"] = os.environ["NETWATCH_TELEGRAM_TOKEN"]
        if os.environ.get("NETWATCH_TELEGRAM_CHAT"):
            tg["chat_id"] = os.environ["NETWATCH_TELEGRAM_CHAT"]
        cfg["telegram"] = tg
    return cfg


def save_config(paths: Paths, cfg: dict):
    paths.ensure()
    tmp = paths.config + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, paths.config)
    paths.fix(paths.config)


# --------------------------------------------------------------------------- database

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
  net TEXT NOT NULL, mac TEXT NOT NULL, ip TEXT, vendor TEXT, hostname TEXT, dtype TEXT,
  ports TEXT, first_seen REAL, last_seen REAL, last_probe REAL,
  PRIMARY KEY (net, mac));
CREATE TABLE IF NOT EXISTS labels(mac TEXT PRIMARY KEY, name TEXT, trusted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, net TEXT, level TEXT, kind TEXT,
  mac TEXT, ip TEXT, message TEXT);
CREATE INDEX IF NOT EXISTS events_net_ts ON events(net, ts);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
"""


class Store:
    def __init__(self, path: str, fix: Callable[[str], None] | None = None):
        self.path = path
        self._tl = threading.local()
        conn = self.conn()
        conn.executescript(SCHEMA)
        conn.commit()
        if fix:
            fix(path)

    def conn(self) -> sqlite3.Connection:
        c = getattr(self._tl, "c", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=15)
            c.row_factory = sqlite3.Row
            self._tl.c = c
        return c

    def close_thread(self):
        c = getattr(self._tl, "c", None)
        if c is not None:
            c.close()
            self._tl.c = None

    def x(self, sql: str, args=()):
        c = self.conn()
        with c:
            c.execute(sql, args)

    def q(self, sql: str, args=()) -> list[sqlite3.Row]:
        return self.conn().execute(sql, args).fetchall()

    # meta
    def meta_get(self, k: str) -> str | None:
        r = self.q("SELECT value FROM meta WHERE key=?", (k,))
        return r[0]["value"] if r else None

    def meta_set(self, k: str, v: str):
        self.x("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v))

    def meta_del(self, k: str):
        self.x("DELETE FROM meta WHERE key=?", (k,))

    # devices
    def devices(self, net: str | None) -> list[dict]:
        if not net:
            return []
        rows = self.q(
            "SELECT d.*, l.name AS name, COALESCE(l.trusted,0) AS trusted FROM devices d "
            "LEFT JOIN labels l ON l.mac=d.mac WHERE d.net=?", (net,))
        out = []
        for r in rows:
            d = dict(r)
            d["ports"] = json.loads(d["ports"]) if d["ports"] is not None else None
            out.append(d)
        return out

    def count(self, net: str) -> int:
        return self.q("SELECT COUNT(*) AS n FROM devices WHERE net=?", (net,))[0]["n"]

    def upsert_device(self, net, mac, ip, vendor, hostname, dtype, ports, first_seen, last_seen, last_probe):
        self.x(
            "INSERT INTO devices(net,mac,ip,vendor,hostname,dtype,ports,first_seen,last_seen,last_probe) "
            "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(net,mac) DO UPDATE SET ip=excluded.ip, vendor=excluded.vendor, "
            "hostname=excluded.hostname, dtype=excluded.dtype, ports=excluded.ports, last_seen=excluded.last_seen, "
            "last_probe=excluded.last_probe",
            (net, mac, ip, vendor, hostname, dtype, None if ports is None else json.dumps(ports),
             first_seen, last_seen, last_probe))

    def forget(self, net: str | None, mac: str):
        if net:
            self.x("DELETE FROM devices WHERE net=? AND mac=?", (net, mac))
        self.x("DELETE FROM labels WHERE mac=?", (mac,))

    # labels (global per MAC: your phone is yours on every network)
    def labels(self) -> dict[str, dict]:
        return {r["mac"]: {"name": r["name"], "trusted": bool(r["trusted"])} for r in self.q("SELECT * FROM labels")}

    def label_set(self, mac: str, name: str | None = None, trusted: bool | None = None):
        cur = self.labels().get(mac, {"name": None, "trusted": False})
        if name is not None:
            cur["name"] = name or None
        if trusted is not None:
            cur["trusted"] = trusted
        self.x("INSERT INTO labels(mac,name,trusted) VALUES(?,?,?) ON CONFLICT(mac) DO UPDATE SET "
               "name=excluded.name, trusted=excluded.trusted", (mac, cur["name"], int(cur["trusted"])))

    # events
    def add_event(self, net, level, kind, message, mac=None, ip=None, now=None):
        self.x("INSERT INTO events(ts,net,level,kind,mac,ip,message) VALUES(?,?,?,?,?,?,?)",
               (now or time.time(), net, level, kind, mac, ip, message))

    def events(self, net: str | None, limit: int = 50) -> list[dict]:
        if not net:
            return []
        return [dict(r) for r in self.q(
            "SELECT ts,level,kind,mac,ip,message FROM events WHERE net=? ORDER BY id DESC LIMIT ?", (net, limit))]

    def prune(self, now: float):
        self.x("DELETE FROM events WHERE ts < ?", (now - EVENT_RETENTION,))


# --------------------------------------------------------------------------- network detection

class NetError(Exception):
    pass


class ScanError(Exception):
    pass


@dataclass
class Net:
    iface: str
    ip: str
    subnet: ipaddress.IPv4Network
    gateway: str | None
    self_mac: str | None
    ssid: str | None
    scan_range: ipaddress.IPv4Network

    @property
    def key(self) -> str:
        return f"{self.ssid or self.iface}@{self.subnet}"

    @property
    def label(self) -> str:
        return f"{self.ssid or self.iface} ({self.subnet})"

    def info(self) -> dict:
        return {"iface": self.iface, "ssid": self.ssid, "subnet": str(self.subnet), "range": str(self.scan_range),
                "gateway": self.gateway, "self_ip": self.ip, "self_mac": self.self_mac, "key": self.key}


def _iface_type(iface: str) -> int:
    try:
        with open(f"/sys/class/net/{iface}/type") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return -1


def _iface_mac(iface: str) -> str | None:
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            m = norm_mac(f.read().strip())
            return None if m in BAD_MACS else m
    except OSError:
        return None


def _default_routes() -> list[tuple[str, str | None, int]]:
    out = []
    try:
        with open("/proc/net/route") as f:
            next(f, None)
            for line in f:
                p = line.split()
                if len(p) < 8:
                    continue
                iface, dest, gw, flags, metric, mask = p[0], p[1], p[2], int(p[3], 16), int(p[6]), p[7]
                if dest == "00000000" and mask == "00000000" and flags & 0x1:
                    gw_ip = socket.inet_ntoa(struct.pack("<L", int(gw, 16))) if flags & 0x2 else None
                    out.append((iface, gw_ip, metric))
    except OSError:
        pass
    return sorted(out, key=lambda r: r[2])


def _iface_ipv4(iface: str) -> tuple[str, str] | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        req = struct.pack("256s", iface.encode()[:15])
        ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, req)[20:24])     # SIOCGIFADDR
        mask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891B, req)[20:24])   # SIOCGIFNETMASK
        return ip, mask
    except OSError:
        return None
    finally:
        s.close()


def _wifi_ssid(iface: str) -> str | None:
    if not (os.path.exists(f"/sys/class/net/{iface}/wireless") or os.path.exists(f"/sys/class/net/{iface}/phy80211")):
        return None
    attempts = (
        (["iwgetid", "-r", iface], lambda out: out.strip()),
        (["iw", "dev", iface, "link"], lambda out: next((l.split("SSID:", 1)[1].strip() for l in out.splitlines() if "SSID:" in l), "")),
        (["nmcli", "-t", "-f", "GENERAL.CONNECTION", "device", "show", iface], lambda out: out.strip().partition(":")[2]),
    )
    for cmd, parse in attempts:
        exe = shutil.which(cmd[0]) or next((p for p in (f"/usr/sbin/{cmd[0]}", f"/sbin/{cmd[0]}") if os.path.exists(p)), None)
        if not exe:
            continue
        try:
            out = subprocess.run([exe] + cmd[1:], capture_output=True, text=True, timeout=3).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        ssid = "".join(ch for ch in parse(out) if ch.isprintable())[:32].strip()
        if ssid:
            return ssid
    return None


def detect_network(iface: str | None = None, subnet: str | None = None) -> Net:
    routes = _default_routes()
    gateway = None
    if iface is None:
        # Prefer a default route on an Ethernet/Wi-Fi interface (type 1); skips VPN tunnels like tun0.
        eth_routes = [r for r in routes if _iface_type(r[0]) == 1 and _iface_ipv4(r[0])]
        if eth_routes:
            iface, gateway = eth_routes[0][0], eth_routes[0][1]
        else:
            for name in sorted(os.listdir("/sys/class/net")) if os.path.isdir("/sys/class/net") else []:
                if name != "lo" and _iface_type(name) == 1 and _iface_ipv4(name):
                    iface = name
                    break
        if iface is None:
            raise NetError("No connected network interface found. Are you on Wi-Fi/Ethernet? (or pass --iface)")
    else:
        if not os.path.exists(f"/sys/class/net/{iface}"):
            raise NetError(f"Interface '{iface}' does not exist")
    if gateway is None:
        gateway = next((r[1] for r in routes if r[0] == iface and r[1]), None)
    addr = _iface_ipv4(iface)
    if not addr:
        raise NetError(f"Interface {iface} has no IPv4 address. Is it connected?")
    ip, mask = addr
    net = ipaddress.ip_interface(f"{ip}/{mask}").network
    if subnet:
        try:
            scan_range = ipaddress.ip_network(subnet, strict=False)
        except ValueError as e:
            raise NetError(f"Bad --subnet: {e}")
        if scan_range.version != 4:
            raise NetError("Only IPv4 subnets are supported")
        if scan_range.num_addresses > 4096:
            raise NetError("--subnet is too large (max 4096 addresses, e.g. a /20)")
    elif net.prefixlen >= 31:
        raise NetError(f"{iface} is a point-to-point link ({net}). Pick your LAN interface with --iface")
    elif net.num_addresses > 1024:
        scan_range = ipaddress.ip_interface(f"{ip}/24").network
        print(yellow(f"note: {net} is large; scanning {scan_range} only (use --subnet to change)"), file=sys.stderr)
    else:
        scan_range = net
    return Net(iface=iface, ip=ip, subnet=net, gateway=gateway, self_mac=_iface_mac(iface),
               ssid=_wifi_ssid(iface), scan_range=scan_range)


def vm_hint(net: Net) -> str | None:
    vm = VM_PREFIXES.get((net.self_mac or "")[:8])
    if not vm:
        return None
    return (f"Kali seems to be running in a {vm} VM. If you only see 1-2 devices, the VM is using NAT "
            "networking and can't see your real network: set the VM's network adapter to 'Bridged'.")


# --------------------------------------------------------------------------- discovery

def read_arp_cache(iface: str | None = None) -> dict[str, str]:
    out = {}
    try:
        with open("/proc/net/arp") as f:
            next(f, None)
            for line in f:
                p = line.split()
                if len(p) < 6 or (iface and p[5] != iface):
                    continue
                if int(p[2], 16) & 0x2:  # ATF_COM: entry is complete
                    mac = norm_mac(p[3])
                    if mac and mac not in BAD_MACS:
                        out[p[0]] = mac
    except (OSError, ValueError):
        pass
    return out


def discover_arpscan(net: Net) -> list[tuple[str, str]]:
    exe = shutil.which("arp-scan") or "/usr/sbin/arp-scan"
    cmd = [exe, "-I", net.iface, "-q", "-x", "-r", "2", str(net.scan_range)]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as e:
        raise ScanError(f"arp-scan failed: {e}")
    if res.returncode != 0:
        raise ScanError(f"arp-scan failed: {(res.stderr or res.stdout).strip()[:200]}")
    pairs = []
    for line in res.stdout.splitlines():
        p = line.split()
        if len(p) >= 2:
            pairs.append((p[0], p[1]))
    return pairs


def discover_scapy(net: Net) -> list[tuple[str, str]]:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
    except Exception as e:  # noqa: BLE001
        raise ScanError(f"scapy unavailable: {e}")
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net.scan_range)),
                     iface=net.iface, timeout=2, retry=1, multi=True, verbose=0)
    except Exception as e:  # noqa: BLE001
        raise ScanError(f"scapy scan failed: {e}")
    return [(r[ARP].psrc, r[ARP].hwsrc) for _, r in ans if ARP in r and r[ARP].op == 2]


def discover_kernel(net: Net) -> list[tuple[str, str]]:
    """No-root fallback: poke every address with a UDP packet so the kernel ARPs for it."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    try:
        for _ in range(2):
            for host in net.scan_range.hosts():
                if str(host) != net.ip:
                    try:
                        s.sendto(b"", (str(host), 9))
                    except OSError:
                        pass
            time.sleep(1.2)
    finally:
        s.close()
    time.sleep(0.8)
    return [(ip, mac) for ip, mac in read_arp_cache(net.iface).items()
            if ipaddress.ip_address(ip) in net.scan_range]


METHODS = {"arp-scan": discover_arpscan, "scapy": discover_scapy, "kernel": discover_kernel}


def method_available(name: str) -> tuple[bool, str]:
    root = os.geteuid() == 0
    if name == "kernel":
        return True, ""
    if not root:
        return False, f"{name} needs root (run with sudo)"
    if name == "arp-scan" and not (shutil.which("arp-scan") or os.path.exists("/usr/sbin/arp-scan")):
        return False, "arp-scan is not installed (sudo apt install arp-scan)"
    if name == "scapy" and importlib.util.find_spec("scapy") is None:
        return False, "scapy is not installed (sudo apt install python3-scapy)"
    return True, ""


def pick_method(pref: str) -> str:
    if pref != "auto":
        ok, why = method_available(pref)
        if not ok:
            die(why)
        return pref
    for m in ("arp-scan", "scapy"):
        if method_available(m)[0]:
            return m
    return "kernel"


def resolve_hostnames(ips: list[str], timeout: float = 2.5) -> dict[str, str]:
    out: dict[str, str] = {}

    def work(ip):
        try:
            name = clean_hostname(socket.gethostbyaddr(ip)[0], ip)
            if name:
                out[ip] = name
        except (OSError, UnicodeError):
            pass

    threads = [threading.Thread(target=work, args=(ip,), daemon=True) for ip in ips]
    for t in threads:
        t.start()
    deadline = time.time() + timeout
    for t in threads:
        t.join(max(0.0, deadline - time.time()))
    return dict(out)


def probe_ports(ips: list[str], ports=tuple(PORTS), timeout: float = 0.7) -> dict[str, list[int]]:
    res: dict[str, list[int]] = {ip: [] for ip in ips}

    def check(job):
        ip, port = job
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return ip, port, True
        except OSError:
            return ip, port, False

    jobs = [(ip, p) for ip in ips for p in ports]
    with ThreadPoolExecutor(max_workers=min(128, max(1, len(jobs)))) as ex:
        for ip, port, ok in ex.map(check, jobs):
            if ok:
                res[ip].append(port)
    return {ip: sorted(p) for ip, p in res.items()}


class OUI:
    """MAC prefix -> vendor, using the databases that ship with nmap / arp-scan on Kali."""
    PATHS = ("/usr/share/nmap/nmap-mac-prefixes", "/usr/share/arp-scan/ieee-oui.txt",
             "/usr/share/ieee-data/oui.txt", "/var/lib/ieee-data/oui.txt", "/usr/share/wireshark/manuf")

    def __init__(self):
        self._db: dict[str, str] | None = None
        self._lock = threading.Lock()

    def _load(self) -> dict[str, str]:
        db: dict[str, str] = {}
        for path in self.PATHS:
            try:
                f = open(path, encoding="utf-8", errors="replace")
            except OSError:
                continue
            with f:
                for line in f:
                    if not line.strip() or line.startswith("#"):
                        continue
                    m = re.match(r"\s*([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)", line)
                    if m:
                        db.setdefault((m.group(1) + m.group(2) + m.group(3)).upper(), m.group(4).strip())
                        continue
                    parts = line.rstrip("\n").split(None, 1)
                    if len(parts) != 2:
                        continue
                    token, name = parts
                    bits = None
                    if "/" in token:
                        token, _, b = token.partition("/")
                        bits = int(b) if b.isdigit() else None
                    hexpart = re.sub(r"[:\-.]", "", token).upper()
                    if bits:
                        hexpart = hexpart[: bits // 4]
                    if re.fullmatch(r"[0-9A-F]{6,9}", hexpart):
                        name = name.split("\t")[-1].strip()
                        db.setdefault(hexpart, name)
            if len(db) > 1000:
                break
        return db

    def lookup(self, mac: str) -> str:
        with self._lock:
            if self._db is None:
                self._db = self._load()
        h = mac.replace(":", "").upper()
        for n in (9, 7, 6):
            v = self._db.get(h[:n])
            if v:
                return v[:40]
        if is_private_mac(mac):
            return "Private (randomized) MAC"
        return "Unknown vendor"


OUI_DB = OUI()

# --------------------------------------------------------------------------- device fingerprinting

TYPE_CAT = {
    "This computer": "laptop", "Router / Gateway": "router", "Network gear": "router",
    "iPhone / iPad": "phone", "Apple device": "phone", "Phone": "phone", "Phone / laptop (private MAC)": "phone",
    "Mac": "laptop", "Windows PC": "laptop", "Windows PC / Xbox": "laptop", "Linux computer": "laptop",
    "Laptop / PC": "laptop", "Smart TV / streamer": "tv", "Chromecast / Google TV": "tv", "Game console": "tv",
    "Amazon Echo / Fire TV": "speaker", "Smart speaker": "speaker", "Google / Nest device": "speaker",
    "IP camera": "camera", "Printer": "printer", "NAS / storage": "server", "Raspberry Pi": "chip",
    "IoT device": "chip", "Smart home hub": "chip", "Unknown device": "unknown",
}

HOST_HINTS = [
    (r"iphone|ipad", "iPhone / iPad"),
    (r"macbook|imac|mac-?mini|mbp|mac-?pro|mac-?studio", "Mac"),
    (r"android|galaxy|pixel|redmi|poco|oneplus|xiaomi|oppo|vivo|motorola|nokia|-phone|phone-", "Phone"),
    (r"^desktop-|^laptop-|-pc$|^win-|windows", "Windows PC"),
    (r"raspberry|^rpi|^pi-|pihole|pi-hole", "Raspberry Pi"),
    (r"chromecast|google-?tv", "Chromecast / Google TV"),
    (r"xbox|playstation|^ps[345]|nintendo", "Game console"),
    (r"(^|[-_])tv([-_]|$)|bravia|roku|fire-?tv|firestick|shield|apple-?tv|webos|tizen", "Smart TV / streamer"),
    (r"echo|alexa|homepod|sonos|google-?home|nest-?(mini|audio|hub)", "Smart speaker"),
    (r"printer|officejet|laserjet|deskjet|envy|^epson|^brw|^npi|^hp[0-9a-f]{6}", "Printer"),
    (r"(^|[-_])cam(era)?([-_0-9]|$)|ipcam|doorbell|reolink|hikvision|wyze", "IP camera"),
    (r"^esp[-_]|esp32|esp8266|tasmota|shelly|tuya|wled|sonoff|smart-?plug", "IoT device"),
    (r"synology|diskstation|qnap|(^|[-_])nas([-_0-9]|$)", "NAS / storage"),
    (r"kali|ubuntu|debian|fedora|archlinux|linux", "Linux computer"),
]

VENDOR_RULES = [
    (("raspberry",), "Raspberry Pi"),
    (("espressif", "tuya", "ai-thinker", "beken", "gaoshengda", "itead", "shelly", "allterco"), "IoT device"),
    (("hikvision", "dahua", "reolink", "wyze", "ring llc", "arlo", "axis comm", "amcrest", "eufy", "foscam",
      "ezviz", "uniview"), "IP camera"),
    (("sonos", "bose", "harman", "bang & olufsen", "denon"), "Smart speaker"),
    (("amazon",), "Amazon Echo / Fire TV"),
    (("roku", "vizio", "tcl", "hisense", "lg electronics", "lg innotek", "tp vision", "sharp", "panasonic"),
     "Smart TV / streamer"),
    (("nintendo", "sony interactive"), "Game console"),
    (("synology", "qnap", "western digital", "seagate", "buffalo", "asustor"), "NAS / storage"),
    (("brother", "canon", "epson", "lexmark", "xerox", "kyocera", "ricoh", "konica"), "Printer"),
    (("signify", "philips lighting", "ikea", "ecobee", "nest labs", "lutron"), "Smart home hub"),
    (("tp-link", "tplink", "netgear", "ubiquiti", "d-link", "linksys", "mikrotik", "zyxel", "cisco", "aruba",
      "eero", "arris", "technicolor", "sagemcom", "zte", "juniper", "avm", "asustek", "tenda", "mercusys",
      "huawei", "actiontec", "askey", "calix", "plume"), "_network"),
    (("google",), "_google"),
    (("apple",), "_apple"),
    (("samsung",), "_samsung"),
    (("microsoft",), "Windows PC / Xbox"),
    (("sony",), "Smart TV / streamer"),
    (("intel", "liteon", "lite-on", "azurewave", "hon hai", "foxconn", "realtek", "mediatek", "qualcomm",
      "rivet", "dell", "lenovo", "micro-star", "gigabyte", "chicony", "wistron", "quanta", "compal",
      "universal global", "cloud network", "hewlett", "hp inc", "framework", "ampak", "fugui"), "Laptop / PC"),
    (("xiaomi", "oneplus", "oppo", "vivo", "motorola", "honor", "realme", "nothing tech", "fairphone", "htc",
      "nokia", "huaqin", "longcheer", "wingtech"), "Phone"),
]


def guess_type(vendor: str, ports, mac: str, hostname: str, is_gateway: bool, is_self: bool) -> str:
    if is_self:
        return "This computer"
    if is_gateway:
        return "Router / Gateway"
    hn = (hostname or "").lower()
    for pattern, label in HOST_HINTS:
        if hn and re.search(pattern, hn):
            return label
    p = set(ports or [])
    if 62078 in p:
        return "iPhone / iPad"
    if 554 in p:
        return "IP camera"
    if p & {9100, 631}:
        return "Printer"
    if p & {8008, 8009}:
        return "Chromecast / Google TV"
    if 3389 in p:
        return "Windows PC"
    if 1883 in p:
        return "Smart home hub"
    v = (vendor or "").lower()
    for keywords, label in VENDOR_RULES:
        if any(k in v for k in keywords):
            if label == "_network":
                if ports is None or p & {53, 80, 443, 8080, 8443}:
                    return "Network gear"
                if "huawei" in v:
                    return "Phone"
                if "asustek" in v:
                    return "Laptop / PC"
                return "IoT device"
            if label == "_google":
                return "Google / Nest device"
            if label == "_apple":
                return "Mac" if p & {22, 445, 5900} else "Apple device"
            if label == "_samsung":
                return "Phone"
            return label
    if p & {445, 139}:
        return "Laptop / PC"
    if 22 in p:
        return "Linux computer"
    if is_private_mac(mac):
        return "Phone / laptop (private MAC)"
    return "Unknown device"


# --------------------------------------------------------------------------- alerts

@dataclass
class Alert:
    level: str          # info | warn | crit
    title: str
    lines: list[str] = field(default_factory=list)


def telegram_api(token: str, method: str, params: dict | None = None, timeout: float = 15):
    if not TOKEN_RE.match(token or ""):
        return False, "invalid bot token format"
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/{method}",
                                 data=urllib.parse.urlencode(params or {}).encode())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read().decode())
        except (ValueError, OSError):
            return False, f"HTTP {e.code}"
    except (urllib.error.URLError, OSError, ValueError) as e:
        return False, str(getattr(e, "reason", e))
    if not data.get("ok"):
        return False, data.get("description", "unknown error")
    return True, data.get("result")


TG_ICON = {"crit": "\U0001F6A8", "warn": "⚠️", "info": "ℹ️"}


def format_telegram(alerts: list[Alert], net_label: str) -> str:
    esc = html.escape
    parts: list[str] = []
    size = 0
    for i, a in enumerate(alerts):
        block = f"{TG_ICON.get(a.level, '')} <b>{esc(a.title)}</b>"
        if a.lines:
            block += "\n" + "\n".join(esc(line[:200]) for line in a.lines[:15])
        if size + len(block) > 3600:
            parts.append(f"…and {len(alerts) - i} more (see the dashboard)")
            break
        parts.append(block)
        size += len(block) + 2
    return "\n\n".join(parts) + f"\n\n<i>NetWatch · {esc(net_label)}</i>"


def desktop_notify(title: str, body: str, critical: bool):
    exe = shutil.which("notify-send")
    if not exe:
        return
    cmd = [exe, "-a", "NetWatch", "-u", "critical" if critical else "normal", title, body]
    user, uid = os.environ.get("SUDO_USER"), os.environ.get("SUDO_UID")
    if os.geteuid() == 0:
        if not (user and uid and uid.isdigit()):
            return
        bus = f"/run/user/{uid}/bus"
        if not os.path.exists(bus):
            return
        cmd = ["sudo", "-u", user, "env", f"DBUS_SESSION_BUS_ADDRESS=unix:path={bus}"] + cmd
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass


class Notifier:
    def __init__(self, cfg: dict, telegram: bool = True, desktop: bool = True):
        tg = cfg.get("telegram") or {}
        self.token = tg.get("token") if telegram else None
        self.chat = tg.get("chat_id") if telegram else None
        self.desktop = desktop
        self._threads: list[threading.Thread] = []

    @property
    def telegram_ready(self) -> bool:
        return bool(self.token and self.chat)

    def send(self, alerts: list[Alert], net_label: str = ""):
        if not alerts:
            return
        for a in alerts:
            tag = {"crit": red("[!!]"), "warn": yellow("[!] "), "info": cyan("[i] ")}.get(a.level, "[ ] ")
            title = red(a.title) if a.level == "crit" else bold(a.title)
            print(f"{tag} {title}")
            for line in a.lines:
                print(f"      {line}")
        t = threading.Thread(target=self._deliver, args=(alerts, net_label), daemon=True)
        t.start()
        self._threads.append(t)
        self._threads = [x for x in self._threads if x.is_alive()]

    def _deliver(self, alerts: list[Alert], net_label: str):
        if self.telegram_ready:
            ok, err = telegram_api(self.token, "sendMessage", {
                "chat_id": self.chat, "text": format_telegram(alerts, net_label),
                "parse_mode": "HTML", "disable_web_page_preview": "true"})
            if not ok:
                print(yellow(f"[telegram] could not send alert: {err}"), file=sys.stderr)
        if self.desktop:
            worst = "crit" if any(a.level == "crit" for a in alerts) else alerts[0].level
            first = alerts[0]
            title = first.title if len(alerts) == 1 else f"{len(alerts)} NetWatch alerts"
            body = "\n".join(first.lines[:4])
            desktop_notify(title, body, worst == "crit")

    def flush(self, timeout: float = 20):
        deadline = time.time() + timeout
        for t in self._threads:
            t.join(max(0.0, deadline - time.time()))


# --------------------------------------------------------------------------- the scan engine

@dataclass
class Deps:
    discover: Callable[[Net], list]
    resolve: Callable[[list], dict]
    probe: Callable[[list], dict] | None
    vendor: Callable[[str], str]
    arp_cache: Callable[[], dict]


def real_deps(net: Net, method: str, probe: bool = True) -> Deps:
    return Deps(discover=METHODS[method], resolve=resolve_hostnames,
                probe=probe_ports if probe else None, vendor=OUI_DB.lookup,
                arp_cache=lambda: read_arp_cache(net.iface))


@dataclass
class ScanResult:
    online: int
    new: int
    baseline: bool
    alerts: list[Alert]
    seen: set
    new_macs: set = field(default_factory=set)
    duration: float = 0.0


def nice(dev: dict) -> str:
    return dev.get("name") or dev.get("hostname") or dev.get("dtype") or dev.get("mac")


def device_lines(dev: dict) -> list[str]:
    lines = [f"IP: {dev['ip']}",
             f"MAC: {dev['mac']}" + ("  (randomized / private)" if is_private_mac(dev["mac"]) else ""),
             f"Vendor: {dev['vendor']}", f"Looks like: {dev['dtype']}"]
    if dev.get("hostname"):
        lines.append(f"Hostname: {dev['hostname']}")
    if dev.get("ports"):
        lines.append("Open ports: " + ", ".join(port_name(p) for p in dev["ports"]))
    for p in risky(dev.get("ports")):
        lines.append(f"Risk: {PORTS[p][0]} ({p}): {PORTS[p][1]}")
    return lines


def process_scan(store: Store, net: Net, deps: Deps, now: float | None = None) -> ScanResult:
    t0 = time.time()
    now = now or t0
    key, gw = net.key, net.gateway

    pairs = set()
    for ip, mac in deps.discover(net):
        mac = norm_mac(mac)
        if not mac or mac in BAD_MACS:
            continue
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.version != 4 or (a not in net.subnet and a not in net.scan_range) or str(a) == net.ip:
            continue
        pairs.add((str(a), mac))

    by_ip: dict[str, set] = {}
    by_mac: dict[str, set] = {}
    for ip, mac in pairs:
        by_ip.setdefault(ip, set()).add(mac)
        by_mac.setdefault(mac, set()).add(ip)

    existing = {d["mac"]: d for d in store.devices(key)}
    labels = store.labels()
    baseline = not existing
    gw_expected = store.meta_get(f"gw:{key}")

    # one IP per MAC for the device list
    current: dict[str, str] = {}
    for mac, ips in by_mac.items():
        prev = existing[mac]["ip"] if mac in existing else None
        others = sorted((i for i in ips if i != gw), key=ip_key)
        if gw in ips and gw_expected in (None, mac):
            current[mac] = gw
        elif prev in others:
            current[mac] = prev
        elif others:
            current[mac] = others[0]
        else:
            current[mac] = gw
    if net.self_mac:
        current[net.self_mac] = net.ip

    targets = [m for m in current if m != net.self_mac]
    probe_set: set[str] = set()
    if deps.probe:
        probe_set = {m for m in targets if m not in existing or not existing[m]["last_probe"]
                     or now - existing[m]["last_probe"] > PROBE_REFRESH}
    names = deps.resolve([current[m] for m in targets]) if targets else {}
    ports = deps.probe(sorted({current[m] for m in probe_set})) if probe_set else {}

    alerts: list[Alert] = []
    new_devs: list[dict] = []
    risky_existing: list[tuple[dict, list[int]]] = []
    baseline_risky: list[tuple[dict, list[int]]] = []
    new_macs: set[str] = set()
    new_count = 0

    for mac, ip in sorted(current.items(), key=lambda kv: ip_key(kv[1])):
        old = existing.get(mac)
        is_self = mac == net.self_mac
        if is_self:
            hostname = clean_hostname(socket.gethostname(), ip)
        else:
            hostname = names.get(ip) or (old["hostname"] if old else "") or ""
        if mac in probe_set:
            p, last_probe = sorted(ports.get(ip, [])), now
        elif old:
            p, last_probe = old["ports"], old["last_probe"]
        else:
            p, last_probe = None, None
        vendor = deps.vendor(mac)
        is_gw = ip == gw and gw_expected in (None, mac)
        dtype = guess_type(vendor, p, mac, hostname, is_gw, is_self)
        store.upsert_device(key, mac, ip, vendor, hostname, dtype, p,
                            old["first_seen"] if old else now, now, last_probe)
        if is_self and mac not in labels:
            store.label_set(mac, trusted=True)
            labels[mac] = {"name": None, "trusted": True}
        lbl = labels.get(mac) or {}
        dev = {"mac": mac, "ip": ip, "vendor": vendor, "hostname": hostname, "dtype": dtype,
               "ports": p, "name": lbl.get("name")}
        risky_now = risky(p)

        if old is None and not is_self:
            if baseline:
                if risky_now:
                    baseline_risky.append((dev, risky_now))
                    store.add_event(key, "warn", "risky_port",
                                    f"{nice(dev)} ({ip}) has {', '.join(port_name(x) for x in risky_now)} open",
                                    mac, ip, now)
            else:
                new_count += 1
                if lbl.get("trusted"):
                    store.add_event(key, "info", "new_device", f"Trusted device {nice(dev)} joined ({ip})", mac, ip, now)
                else:
                    desc = f"{dtype}, {vendor}" + (f", {hostname}" if hostname else "")
                    store.add_event(key, "warn", "new_device", f"New device joined: {ip} ({desc})", mac, ip, now)
                    new_devs.append(dev)
                    new_macs.add(mac)
        elif old is not None:
            if old["ip"] != ip:
                store.add_event(key, "info", "ip_change", f"{nice(dev)} changed IP {old['ip']} → {ip}", mac, ip, now)
            if mac in probe_set:
                newly = [x for x in risky_now if x not in set(old["ports"] or [])]
                if newly:
                    store.add_event(key, "warn", "risky_port",
                                    f"{nice(dev)} ({ip}) opened {', '.join(port_name(x) for x in newly)}", mac, ip, now)
                    risky_existing.append((dev, newly))

    if baseline:
        lines = [f"Baseline: {len(current)} devices recorded on {net.label}.",
                 "You'll get an alert when an unknown device joins."]
        if baseline_risky:
            lines.append("Risky open ports found:")
            for dev, rp in baseline_risky:
                lines.append(f"- {nice(dev)} ({dev['ip']}): " + ", ".join(port_name(x) for x in rp))
        alerts.append(Alert("info", "NetWatch is now watching your network", lines))
        store.meta_set(f"baseline:{key}", str(now))
        store.add_event(key, "info", "baseline", f"Started watching: {len(current)} devices recorded", now=now)

    if len(new_devs) > 5:
        alerts.append(Alert("warn", f"{len(new_devs)} new devices joined your network",
                            [f"- {d['ip']}  {d['dtype']} ({d['vendor']})" for d in new_devs]))
    else:
        for dev in new_devs:
            alerts.append(Alert("warn", "New device joined your network", device_lines(dev)))
    for dev, newly in risky_existing:
        alerts.append(Alert("warn", "Risky port opened", [f"Device: {nice(dev)} ({dev['ip']})"] +
                            [f"{PORTS[x][0]} ({x}): {PORTS[x][1]}" for x in newly]))

    # ---- ARP spoofing / man-in-the-middle detection
    if gw:
        gw_macs = by_ip.get(gw, set())
        cache_gw = deps.arp_cache().get(gw)
        if gw_expected is None:
            if len(gw_macs) == 1:
                gw_expected = next(iter(gw_macs))
                store.meta_set(f"gw:{key}", gw_expected)
            elif len(gw_macs) > 1:
                alerts.append(Alert("crit", "Several devices claim to be your router", [
                    f"Router IP {gw} answered from: " + ", ".join(f"{m} ({deps.vendor(m)})" for m in sorted(gw_macs)),
                    "This is a classic sign of ARP spoofing (man-in-the-middle).",
                    "NetWatch will learn the real router MAC once only one device answers."]))
                store.add_event(key, "crit", "arp_spoof", f"Several MACs claim the router IP {gw}", ip=gw, now=now)
        if gw_expected:
            observed = set(gw_macs) | ({cache_gw} if cache_gw else set())
            bad = sorted(observed - {gw_expected})
            sig = ",".join(bad)
            prev_sig = store.meta_get(f"gwalert:{key}") or ""
            if bad and sig != prev_sig:
                lines = [f"Router IP: {gw}", f"Real router MAC: {gw_expected} ({deps.vendor(gw_expected)})"]
                for m in bad:
                    also = sorted(by_mac.get(m, set()) - {gw})
                    where = "answering ARP" if m in gw_macs else "in this computer's ARP cache (you are being poisoned)"
                    lines.append(f"Impostor: {m} ({deps.vendor(m)}) {where}" +
                                 (f", whose own IP is {', '.join(also)}" if also else ""))
                lines += ["Someone may be intercepting traffic (ARP spoofing / man-in-the-middle).",
                          "Just replaced your router? Run: netwatch.py accept-gateway"]
                alerts.append(Alert("crit", "Possible man-in-the-middle attack", lines))
                store.add_event(key, "crit", "arp_spoof",
                                f"Router {gw} is being impersonated by {', '.join(bad)}", ip=gw, now=now)
                store.meta_set(f"gwalert:{key}", sig)
            elif not bad and prev_sig and gw_macs:
                alerts.append(Alert("info", "Router back to normal",
                                    [f"Only the real router ({gw_expected}) answers for {gw} again."]))
                store.add_event(key, "info", "arp_spoof_clear", "Router MAC back to normal", ip=gw, now=now)
                store.meta_del(f"gwalert:{key}")

    dups = sorted(f"{ip}={'/'.join(sorted(macs))}" for ip, macs in by_ip.items() if len(macs) > 1 and ip != gw)
    dup_sig, prev_dup = ";".join(dups), store.meta_get(f"dup:{key}") or ""
    if dups and dup_sig != prev_dup:
        alerts.append(Alert("warn", "IP address conflict", [
            f"{d.split('=')[0]} is answered by {d.split('=')[1].replace('/', ' and ')}" for d in dups] +
            ["Usually a misconfigured device, but it can also be ARP spoofing."]))
        store.add_event(key, "warn", "ip_conflict", "IP conflict: " + ", ".join(dups), now=now)
    if dup_sig != prev_dup:
        if dup_sig:
            store.meta_set(f"dup:{key}", dup_sig)
        else:
            store.meta_del(f"dup:{key}")

    store.meta_set(f"last_scan:{key}", str(now))
    store.meta_set(f"net_info:{key}", json.dumps(net.info()))
    store.meta_set("last_net", key)
    store.prune(now)
    return ScanResult(online=len(current), new=new_count, baseline=baseline, alerts=alerts,
                      seen=set(current), new_macs=new_macs, duration=time.time() - t0)


# --------------------------------------------------------------------------- terminal table

def sort_devices(devs: list[dict], gateway: str | None) -> list[dict]:
    return sorted(devs, key=lambda d: (0 if d["ip"] == gateway else 1, ip_key(d["ip"] or "0.0.0.0")))


def print_table(devs: list[dict], info: dict, is_online: Callable[[dict], bool], new_macs=frozenset(),
                baseline_at: float = 0):
    width = shutil.get_terminal_size((130, 24)).columns
    cols = [("", 6), ("IP", 15), ("NAME", 24), ("TYPE", 24), ("VENDOR", 20), ("MAC", 17), ("PORTS", 18)]
    drop = set()
    if width < 128:
        drop.add("VENDOR")
    if width < 106:
        drop.add("PORTS")
    if width < 86:
        drop.add("MAC")
    cols = [c for c in cols if c[0] not in drop]
    online = sum(1 for d in devs if is_online(d))
    print()
    print(bold(" NETWATCH ") + dim(f" {info.get('iface')} · {info.get('ssid') or 'wired'} · {info.get('subnet')}"
                                   f" · gateway {info.get('gateway') or '?'}") + "   " + green(f"{online} online")
          + dim(f" / {len(devs)} known"))
    print(dim(" " + " ".join(fit(name, w) for name, w in cols)))
    for d in sort_devices(devs, info.get("gateway")):
        on = is_online(d)
        cells = []
        for name, w in cols:
            if name == "":
                dot = green("●") if on else dim("○")
                if d["mac"] in new_macs and not d["trusted"]:
                    tag = red(fit("NEW", w - 2))
                elif d["trusted"]:
                    tag = green(fit("✓", w - 2))
                else:
                    tag = " " * (w - 2)
                cells.append(f"{dot} {tag}")
                continue
            if name == "IP":
                text = d["ip"]
            elif name == "NAME":
                text = (d.get("name") or d.get("hostname") or "-") + (" (you)" if d["dtype"] == "This computer" else "")
            elif name == "TYPE":
                text = d["dtype"]
            elif name == "VENDOR":
                text = d["vendor"]
            elif name == "MAC":
                text = d["mac"]
            else:
                ports = d["ports"]
                text = "-" if ports is None else ",".join(f"{p}!" if p in risky(ports) else str(p) for p in ports) or "none"
            cell = fit(text, w)
            if name == "PORTS" and risky(d["ports"]):
                cell = red(cell)
            elif not on:
                cell = dim(cell)
            cells.append(cell)
        print(" " + " ".join(cells))
    print()


def online_fn(window: float, now: float | None = None):
    now = now or time.time()
    return lambda d: (now - (d["last_seen"] or 0)) <= window


# --------------------------------------------------------------------------- web dashboard

class Shared:
    def __init__(self):
        self._lock = threading.Lock()
        self._d: dict = {}

    def update(self, **kw):
        with self._lock:
            self._d.update(kw)

    def get(self) -> dict:
        with self._lock:
            return dict(self._d)


def build_state(store: Store, shared: Shared) -> dict:
    s = shared.get()
    key = s.get("key")
    net = s.get("network") or {}
    devs = []
    for d in store.devices(key):
        devs.append({
            "mac": d["mac"], "ip": d["ip"], "vendor": d["vendor"] or "", "hostname": d["hostname"] or "",
            "name": d["name"] or "", "type": d["dtype"] or "Unknown device",
            "cat": TYPE_CAT.get(d["dtype"], "unknown"), "ports": d["ports"], "trusted": bool(d["trusted"]),
            "first_seen": d["first_seen"], "last_seen": d["last_seen"], "private": is_private_mac(d["mac"]),
            "is_gateway": d["dtype"] == "Router / Gateway", "is_self": d["mac"] == net.get("self_mac"),
        })
    gw_alert = dup = None
    baseline_at = 0.0
    if key:
        sig = store.meta_get(f"gwalert:{key}")
        if sig:
            gw_alert = {"expected": store.meta_get(f"gw:{key}"), "seen": sig.split(","), "gateway": net.get("gateway")}
        d = store.meta_get(f"dup:{key}")
        dup = d.split(";") if d else None
        baseline_at = float(store.meta_get(f"baseline:{key}") or 0)
    return {
        "version": VERSION, "now": time.time(), "network": net, "baseline_at": baseline_at,
        "scan": {"last": s.get("scan_last"), "next": s.get("scan_next"), "running": s.get("running", False),
                 "count": s.get("count", 0), "method": s.get("method"), "interval": s.get("interval"),
                 "error": s.get("error")},
        "online_window": s.get("online_window", 150), "devices": devs, "events": store.events(key, 60),
        "ports": {str(p): [svc, risk] for p, (svc, risk) in PORTS.items()},
        "alerts": {"gateway": gw_alert, "dup": dup}, "demo": s.get("demo", False),
    }


def make_handler(store: Store, shared: Shared, token: str, wake: threading.Event, loopback: bool, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
    if port == 80:
        allowed_hosts |= {"127.0.0.1", "localhost", "[::1]"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "NetWatch"
        sys_version = ""

        def log_message(self, *args):  # keep the terminal clean
            pass

        def _send(self, code: int, body, ctype: str = "application/json", nonce: str | None = None):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            script = f"'nonce-{nonce}'" if nonce else "'none'"
            self.send_header("Content-Security-Policy",
                             f"default-src 'none'; script-src {script}; style-src 'unsafe-inline'; "
                             "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; "
                             "frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(data)

        def _host_ok(self) -> bool:
            # Blocks DNS-rebinding attacks against the localhost dashboard.
            return not loopback or (self.headers.get("Host") or "").lower() in allowed_hosts

        def _authed(self) -> bool:
            return secrets.compare_digest(self.headers.get("X-NetWatch-Token", "").encode(), token.encode())

        def do_GET(self):
            try:
                if not self._host_ok():
                    return self._send(403, {"error": "bad host"})
                url = urllib.parse.urlsplit(self.path)
                if url.path == "/":
                    if not loopback:
                        given = urllib.parse.parse_qs(url.query).get("token", [""])[0]
                        if not secrets.compare_digest(given.encode(), token.encode()):
                            return self._send(403, b"Forbidden: open the full URL (with ?token=...) "
                                                   b"printed in the NetWatch terminal.", "text/plain; charset=utf-8")
                    nonce = secrets.token_urlsafe(16)
                    page = DASHBOARD_HTML.replace("__NETWATCH_TOKEN__", token).replace("__NONCE__", nonce)
                    return self._send(200, page.encode(), "text/html; charset=utf-8", nonce=nonce)
                if url.path == "/api/state":
                    if not self._authed():
                        return self._send(401, {"error": "unauthorized"})
                    return self._send(200, build_state(store, shared))
                self._send(404, {"error": "not found"})
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                store.close_thread()

        def do_POST(self):
            try:
                if not self._host_ok():
                    return self._send(403, {"error": "bad host"})
                if not self._authed():
                    return self._send(401, {"error": "unauthorized"})
                if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                    return self._send(415, {"error": "JSON only"})
                length = int(self.headers.get("Content-Length") or 0)
                if length > 4096:
                    return self._send(413, {"error": "too large"})
                try:
                    body = json.loads(self.rfile.read(length) or b"{}")
                except ValueError:
                    return self._send(400, {"error": "bad JSON"})
                if not isinstance(body, dict):
                    return self._send(400, {"error": "bad JSON"})
                path = urllib.parse.urlsplit(self.path).path
                key = shared.get().get("key")
                if path == "/api/scan":
                    wake.set()
                    return self._send(200, {"ok": True})
                if path == "/api/accept-gateway":
                    if key:
                        store.meta_del(f"gw:{key}")
                        store.meta_del(f"gwalert:{key}")
                        store.add_event(key, "info", "gateway_reset", "Router MAC accepted: it will be re-learned on the next scan")
                    wake.set()
                    return self._send(200, {"ok": True})
                if path == "/api/device":
                    mac = norm_mac(str(body.get("mac", "")))
                    action = body.get("action")
                    if not mac:
                        return self._send(400, {"error": "bad mac"})
                    if action == "trust":
                        store.label_set(mac, trusted=True)
                    elif action == "untrust":
                        store.label_set(mac, trusted=False)
                    elif action == "rename":
                        store.label_set(mac, name=clean_label(str(body.get("name", ""))))
                    elif action == "forget":
                        store.forget(key, mac)
                    else:
                        return self._send(400, {"error": "bad action"})
                    return self._send(200, {"ok": True})
                self._send(404, {"error": "not found"})
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                store.close_thread()

    return Handler


def start_dashboard(store, shared, wake, host: str, port: int, self_ip: str | None = None) -> str | None:
    token = secrets.token_hex(16)
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True
        address_family = socket.AF_INET6 if ":" in host else socket.AF_INET

    try:
        server = Server((host, port), make_handler(store, shared, token, wake, loopback, port))
    except OSError as e:
        print(yellow(f"Dashboard could not start on {host}:{port} ({e.strerror}). Try --port 8081"))
        return None
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if loopback:
        return f"http://127.0.0.1:{port}/"
    shown = self_ip if host in ("0.0.0.0", "") else host
    print(yellow("Dashboard is reachable from your network. Anyone with the link can see it, so keep the token private."))
    return f"http://{shown}:{port}/?token={token}"


# --------------------------------------------------------------------------- monitor loop

def run_loop(store: Store, get_net: Callable[[Net | None], Net], make_deps: Callable[[Net], Deps],
             notifier: Notifier, interval: int, dashboard: tuple[str, int, str | None] | None, shared: Shared,
             on_scan: Callable[[int, ScanResult], None] | None = None):
    wake = threading.Event()
    window = interval * 2.5 + 5
    store.meta_set("online_window", str(window))
    shared.update(interval=interval, online_window=window)
    if dashboard:
        url = start_dashboard(store, shared, wake, *dashboard)
        if url:
            print(green("Dashboard: ") + bold(url))
    net: Net | None = None
    deps: Deps | None = None
    n = 0
    hinted = False
    while True:
        try:
            new_net = get_net(net)
        except NetError as e:
            print(yellow(f"[{time.strftime('%H:%M:%S')}] {e}. Retrying in {interval}s"))
            shared.update(error=str(e), running=False, scan_next=time.time() + interval)
            wake.wait(interval)
            wake.clear()
            continue
        if net is None or new_net.key != net.key:
            net = new_net
            deps = make_deps(net)
            print(cyan(f"Watching {net.label}" + (f" on {net.iface}" if net.ssid else "")
                       + f", gateway {net.gateway or 'unknown'}"))
            shared.update(network=net.info(), key=net.key)
        else:
            net = new_net
        shared.update(running=True, error=None)
        try:
            res = process_scan(store, net, deps)
        except ScanError as e:
            print(yellow(f"[{time.strftime('%H:%M:%S')}] {e}. Falling back to the no-root kernel method"))
            deps = make_deps_fallback(net, deps)
            shared.update(running=False, error=str(e), method="kernel")
            continue
        n += 1
        notifier.send(res.alerts, net.label)
        now = time.time()
        shared.update(running=False, scan_last=now, scan_next=now + interval, count=n)
        if n == 1:
            print_table(store.devices(net.key), net.info(), online_fn(window), res.new_macs)
        print(dim(f"[{time.strftime('%H:%M:%S')}] scan #{n}: ") + green(f"{res.online} online")
              + (red(f", {res.new} new") if res.new else "") + dim(f" ({res.duration:.1f}s)"))
        if not hinted and res.online <= 3 and vm_hint(net):
            print(yellow(vm_hint(net)))
            hinted = True
        if on_scan:
            on_scan(n, res)
        wake.wait(interval)
        wake.clear()


def make_deps_fallback(net: Net, deps: Deps) -> Deps:
    return Deps(discover=discover_kernel, resolve=deps.resolve, probe=deps.probe, vendor=deps.vendor,
                arp_cache=deps.arp_cache)


# --------------------------------------------------------------------------- commands

def open_store(paths: Paths) -> Store:
    paths.ensure()
    return Store(paths.db, fix=paths.fix)


def root_note(method: str):
    if os.geteuid() != 0:
        print(yellow("note: not running as root, so using the slower kernel method; results may lag. "
                     "For the best results: sudo python3 netwatch.py ..."))


def cmd_scan(args, paths: Paths):
    net = detect_network(args.iface, args.subnet)
    method = pick_method(args.method)
    root_note(method)
    store = open_store(paths)
    print(dim(f"Scanning {net.scan_range} on {net.iface} using {method}…"))
    try:
        res = process_scan(store, net, real_deps(net, method, probe=not args.no_probe))
    except ScanError as e:
        die(str(e))
    notifier = Notifier(load_config(paths), telegram=args.alert, desktop=args.alert)
    notifier.send(res.alerts, net.label)
    cutoff = float(store.meta_get(f"last_scan:{net.key}") or 0)
    print_table(store.devices(net.key), net.info(), lambda d: (d["last_seen"] or 0) >= cutoff, res.new_macs)
    print(dim(f"{res.online} online · scan took {res.duration:.1f}s"))
    if res.online <= 3 and vm_hint(net):
        print(yellow(vm_hint(net)))
    notifier.flush()


def cmd_monitor(args, paths: Paths):
    first = detect_network(args.iface, args.subnet)  # fail fast with a clear message
    method = pick_method(args.method)
    root_note(method)
    store = open_store(paths)
    cfg = load_config(paths)
    notifier = Notifier(cfg, desktop=not args.no_desktop)
    print(bold(green("◉ NetWatch")) + dim(f" v{VERSION}  ·  scanning every {args.interval}s with {method}  ·  Ctrl+C to stop"))
    if notifier.telegram_ready:
        print(green("Telegram alerts: on"))
    else:
        print(dim("Telegram alerts: off (run `python3 netwatch.py telegram-setup` to get alerts on your phone)"))
    shared = Shared()
    shared.update(method=method)

    def get_net(prev: Net | None) -> Net:
        net = detect_network(args.iface, args.subnet)
        # keep the same network identity if the SSID lookup hiccups
        if prev and net.ssid is None and prev.iface == net.iface and prev.subnet == net.subnet and prev.gateway == net.gateway:
            net.ssid = prev.ssid
        return net

    try:
        run_loop(store, get_net, lambda net: real_deps(net, method, probe=not args.no_probe), notifier,
                 max(15, args.interval), None if args.no_dashboard else (args.host, args.port, first.ip), shared)
    except KeyboardInterrupt:
        print("\nStopping…")
    finally:
        notifier.flush(5)


def cmd_list(args, paths: Paths):
    store = open_store(paths)
    keys = [r["net"] for r in store.q("SELECT DISTINCT net FROM devices ORDER BY net")] if args.all else \
        [k for k in [store.meta_get("last_net")] if k]
    if not keys:
        print("No devices recorded yet. Run: sudo python3 netwatch.py scan")
        return
    window = float(store.meta_get("online_window") or 155)
    for key in keys:
        info = json.loads(store.meta_get(f"net_info:{key}") or "{}") or {"subnet": key}
        print_table(store.devices(key), info, online_fn(window))


def cmd_events(args, paths: Paths):
    store = open_store(paths)
    key = store.meta_get("last_net")
    evs = store.events(key, args.limit)
    if not evs:
        print("No events yet.")
        return
    for e in reversed(evs):
        color = {"crit": red, "warn": yellow, "info": cyan}.get(e["level"], str)
        print(dim(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["ts"]))) + "  " +
              color(fit(e["level"].upper(), 5)) + " " + e["message"])


def resolve_target(store: Store, target: str) -> str:
    mac = norm_mac(target)
    if mac:
        return mac
    t = target.strip().lower()
    devs = store.devices(store.meta_get("last_net"))
    hits = [d for d in devs if d["ip"] == t]
    if not hits:
        hits = [d for d in devs if t in (d.get("name") or "").lower() or t in (d.get("hostname") or "").lower()]
    if len(hits) == 1:
        return hits[0]["mac"]
    if not hits:
        die(f"No device matches '{target}'. Use a MAC, an IP or part of its name (see: netwatch.py list)")
    die(f"'{target}' matches several devices: " + ", ".join(f"{d['ip']} ({d['mac']})" for d in hits))
    return ""


def cmd_label(args, paths: Paths):
    store = open_store(paths)
    mac = resolve_target(store, args.target)
    if args.cmd == "trust":
        store.label_set(mac, name=clean_label(args.name) if args.name else None, trusted=True)
        print(green(f"✓ {mac} is now trusted") + (f" as '{clean_label(args.name)}'" if args.name else ""))
    elif args.cmd == "untrust":
        store.label_set(mac, trusted=False)
        print(f"{mac} is no longer trusted")
    elif args.cmd == "name":
        store.label_set(mac, name=clean_label(args.name))
        print(f"{mac} is now called '{clean_label(args.name)}'")
    elif args.cmd == "forget":
        store.forget(store.meta_get("last_net"), mac)
        print(f"Forgot {mac}. It will be reported as new next time it shows up.")


def cmd_accept_gateway(args, paths: Paths):
    store = open_store(paths)
    key = store.meta_get("last_net")
    if not key:
        die("No network scanned yet")
    store.meta_del(f"gw:{key}")
    store.meta_del(f"gwalert:{key}")
    store.add_event(key, "info", "gateway_reset", "Router MAC accepted: it will be re-learned on the next scan")
    print("OK. The router's MAC address will be re-learned on the next scan.")


def cmd_telegram_setup(args, paths: Paths):
    print(bold("Telegram alerts setup") + "\n"
          "  1. In Telegram, open a chat with @BotFather and send /newbot\n"
          "  2. Pick any name and a username ending in 'bot'\n"
          "  3. BotFather replies with a token like 123456789:AAH...  (keep it secret)\n")
    token = (args.token or getpass.getpass("Paste the bot token (input is hidden): ")).strip()
    if not TOKEN_RE.match(token):
        die("That doesn't look like a bot token (expected something like 123456789:AAH...)")
    ok, me = telegram_api(token, "getMe")
    if not ok:
        die(f"Telegram rejected the token: {me}")
    username = me.get("username", "")
    print(green(f"✓ Found your bot @{username}"))
    print(f"\n  4. Open https://t.me/{username} and press START (or send it any message).\n")
    print(dim("Waiting up to 2 minutes for your message…"))
    chat, who, offset, deadline = None, "", None, time.time() + 120
    while time.time() < deadline and chat is None:
        params = {"timeout": 20}
        if offset:
            params["offset"] = offset
        ok, updates = telegram_api(token, "getUpdates", params, timeout=30)
        if not ok:
            print(yellow(f"  ({updates}) retrying…"))
            time.sleep(3)
            continue
        for u in updates or []:
            offset = u.get("update_id", 0) + 1
            msg = u.get("message") or u.get("edited_message") or {}
            c = msg.get("chat") or {}
            if c.get("id"):
                chat = c["id"]
                who = c.get("first_name") or c.get("title") or c.get("username") or ""
    if chat is None:
        die("No message received. Run telegram-setup again and message your bot.")
    cfg = load_config(paths, env=False)
    cfg["telegram"] = {"token": token, "chat_id": chat}
    save_config(paths, cfg)
    telegram_api(token, "sendMessage", {"chat_id": chat, "text": "✅ NetWatch is connected. You'll get network alerts here."})
    print(green(f"✓ Connected to {who or 'your chat'}. Settings saved to {paths.config}"))
    print("Test it any time with: python3 netwatch.py test-alert")


def cmd_test_alert(args, paths: Paths):
    notifier = Notifier(load_config(paths))
    if not notifier.telegram_ready:
        print(yellow("Telegram is not set up yet. Run: python3 netwatch.py telegram-setup"))
    notifier.send([Alert("info", "Test alert from NetWatch", ["If you can read this, alerts are working."])], "test")
    notifier.flush()


# --------------------------------------------------------------------------- demo mode

DEMO_SELF = ("d4:3b:04:aa:10:50", "192.168.1.50", "Intel Corporate")
DEMO_DEVICES = [
    # mac, ip, vendor, hostname, ports, label, trusted
    ("50:c7:bf:12:34:01", "192.168.1.1", "TP-Link Technologies", "", [53, 80, 443], "Router", True),
    ("f0:98:9d:3a:21:0e", "192.168.1.14", "Apple", "Sams-iPhone", [62078], "Sam's iPhone", True),
    ("3c:22:fb:5e:77:01", "192.168.1.15", "Apple", "Sams-MacBook-Air", [22], None, True),
    ("8c:79:f5:44:10:22", "192.168.1.22", "Samsung Electronics", "Living-Room-TV", [8080], "Living room TV", True),
    ("dc:a6:32:01:02:03", "192.168.1.30", "Raspberry Pi Trading", "pihole", [22, 53, 80], "Pi-hole", True),
    ("44:65:0d:9a:3c:41", "192.168.1.41", "Amazon Technologies", "", [], "Kitchen Echo", True),
    ("a4:5d:36:8b:0c:60", "192.168.1.60", "Hewlett Packard", "HP-OfficeJet", [80, 443, 631, 9100], None, True),
    ("da:7f:3e:21:9c:73", "192.168.1.73", "Private (randomized) MAC", "", [], None, False),
    ("28:57:be:66:e1:88", "192.168.1.88", "Hangzhou Hikvision", "", [80, 554], "Doorbell cam", True),
    ("00:17:88:4b:2a:01", "192.168.1.101", "Philips Lighting", "Philips-hue", [80, 443], None, True),
    ("b0:be:76:12:9f:02", "192.168.1.120", "TP-Link Technologies", "", [9999], None, False),
]
DEMO_INTRUDER = ("24:0a:c4:9e:11:37", "192.168.1.137", "Espressif", "", [23, 80])
DEMO_ATTACKER = ("00:c0:ca:b1:7e:66", "192.168.1.66", "Alfa", "kali", [22])


def cmd_demo(args, paths: Paths):
    tmp = tempfile.mkdtemp(prefix="netwatch-demo-")
    store = Store(os.path.join(tmp, "demo.db"))
    net = Net(iface="wlan0", ip=DEMO_SELF[1], subnet=ipaddress.ip_network("192.168.1.0/24"),
              gateway="192.168.1.1", self_mac=DEMO_SELF[0], ssid="HomeWiFi",
              scan_range=ipaddress.ip_network("192.168.1.0/24"))
    vendors = {m: v for m, _, v, *_ in DEMO_DEVICES + [DEMO_INTRUDER, DEMO_ATTACKER]}
    vendors[DEMO_SELF[0]] = DEMO_SELF[2]
    hosts = {ip: h for _, ip, _, h, *_ in DEMO_DEVICES + [DEMO_INTRUDER, DEMO_ATTACKER] if h}
    ports = {ip: p for _, ip, _, _, p, *_ in DEMO_DEVICES + [DEMO_INTRUDER, DEMO_ATTACKER]}
    for mac, _, _, _, _, label, trusted in DEMO_DEVICES:
        if label or trusted:
            store.label_set(mac, name=label, trusted=trusted)
    state = {"n": 0}

    def discover(_net):
        state["n"] += 1
        n = (state["n"] - 1) % 12 + 1
        found = [(ip, mac) for mac, ip, *_ in DEMO_DEVICES]
        if 2 <= n <= 6:  # Sam's phone leaves for a bit
            found = [f for f in found if f[0] != "192.168.1.14"]
        if state["n"] >= 3:
            found.append((DEMO_INTRUDER[1], DEMO_INTRUDER[0]))
        if 8 <= n <= 10:  # an attacker on the network starts ARP-spoofing the router
            found += [(DEMO_ATTACKER[1], DEMO_ATTACKER[0]), ("192.168.1.1", DEMO_ATTACKER[0])]
        return found

    deps = Deps(discover=discover, resolve=lambda ips: {ip: hosts[ip] for ip in ips if ip in hosts},
                probe=lambda ips: {ip: ports.get(ip, []) for ip in ips},
                vendor=lambda mac: vendors.get(mac) or OUI_DB.lookup(mac), arp_cache=lambda: {})
    shared = Shared()
    shared.update(method="demo", demo=True)
    print(bold(green("◉ NetWatch demo")) + dim(" · simulated network · nothing is really scanned · Ctrl+C to stop"))
    print(dim("Watch for: a phone leaving, an unknown IoT device with Telnet joining, then an ARP-spoofing attack."))
    try:
        run_loop(store, lambda prev: net, lambda _n: deps, Notifier({}, telegram=False, desktop=False),
                 args.interval, ("127.0.0.1", args.port, None), shared)
    except KeyboardInterrupt:
        print("\nDemo stopped.")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- CLI

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netwatch.py", description="NetWatch: home network watchdog. "
                                "Only use on networks you own or are allowed to monitor.")
    p.add_argument("--version", action="version", version=f"NetWatch {VERSION}")
    p.add_argument("--data-dir", help="where to keep the database and settings (default ~/.config/netwatch)")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")

    def scan_opts(sp):
        sp.add_argument("--iface", help="network interface (default: auto-detect, e.g. wlan0)")
        sp.add_argument("--subnet", help="range to scan (default: your LAN, e.g. 192.168.1.0/24)")
        sp.add_argument("--method", choices=["auto", "arp-scan", "scapy", "kernel"], default="auto",
                        help="discovery method (default: best available)")
        sp.add_argument("--no-probe", action="store_true", help="don't check devices for open ports")

    sp = sub.add_parser("monitor", help="watch the network continuously, with alerts and a dashboard")
    scan_opts(sp)
    sp.add_argument("--interval", type=int, default=60, help="seconds between scans (default 60, min 15)")
    sp.add_argument("--port", type=int, default=8080, help="dashboard port (default 8080)")
    sp.add_argument("--host", default="127.0.0.1",
                    help="dashboard address (default 127.0.0.1; use 0.0.0.0 to view it from your phone)")
    sp.add_argument("--no-dashboard", action="store_true", help="don't start the web dashboard")
    sp.add_argument("--no-desktop", action="store_true", help="no desktop pop-up notifications")

    sp = sub.add_parser("scan", help="scan once and print a table of devices")
    scan_opts(sp)
    sp.add_argument("--alert", action="store_true", help="also send Telegram/desktop alerts")

    sp = sub.add_parser("demo", help="try the dashboard on a simulated network (no root needed)")
    sp.add_argument("--port", type=int, default=8080)
    sp.add_argument("--interval", type=int, default=6)

    sp = sub.add_parser("list", help="show known devices (no scan)")
    sp.add_argument("--all", action="store_true", help="show every network you've scanned")

    sp = sub.add_parser("events", help="show recent events and alerts")
    sp.add_argument("--limit", type=int, default=30)

    sp = sub.add_parser("trust", help="mark a device as yours (no alerts for it)")
    sp.add_argument("target", help="MAC, IP, or part of the device's name")
    sp.add_argument("--name", help="also give it a name")
    sp = sub.add_parser("untrust", help="remove trust from a device")
    sp.add_argument("target")
    sp = sub.add_parser("name", help="give a device a friendly name")
    sp.add_argument("target")
    sp.add_argument("name")
    sp = sub.add_parser("forget", help="forget a device (it will alert as new next time)")
    sp.add_argument("target")
    sub.add_parser("accept-gateway", help="accept a new router MAC (after replacing your router)")
    sp = sub.add_parser("telegram-setup", help="connect a Telegram bot for phone alerts")
    sp.add_argument("--token", help=argparse.SUPPRESS)
    sub.add_parser("test-alert", help="send a test alert")
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.no_color:
        Color.enabled = False
    if not args.cmd:
        parser.print_help()
        print("\nTry:  python3 netwatch.py demo            (see the dashboard, no root needed)")
        print("      sudo python3 netwatch.py monitor    (watch your real network)")
        return
    paths = Paths(args.data_dir)
    handlers = {"scan": cmd_scan, "monitor": cmd_monitor, "demo": cmd_demo, "list": cmd_list,
                "events": cmd_events, "trust": cmd_label, "untrust": cmd_label, "name": cmd_label,
                "forget": cmd_label, "accept-gateway": cmd_accept_gateway,
                "telegram-setup": cmd_telegram_setup, "test-alert": cmd_test_alert}
    try:
        handlers[args.cmd](args, paths)
    except NetError as e:
        die(str(e))
    except KeyboardInterrupt:
        print()
    except sqlite3.OperationalError as e:
        die(f"database problem ({e}). If you ran with sudo before, try sudo again.")


# --------------------------------------------------------------------------- dashboard page

DASHBOARD_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWatch</title>
<style>
:root{--bg:#0a0e13;--panel:#10161e;--panel2:#151d27;--line:#1d2834;--line2:#2a3746;--text:#dbe4ec;--muted:#8391a0;--faint:#5a6774;
--green:#3ee08f;--greenbg:rgba(62,224,143,.12);--amber:#f6b93b;--amberbg:rgba(246,185,59,.12);--red:#ff5f5f;--redbg:rgba(255,95,95,.12);
--blue:#5eb1ff;--bluebg:rgba(94,177,255,.12);--mono:ui-monospace,"JetBrains Mono","Fira Code",Menlo,Consolas,"DejaVu Sans Mono",monospace;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,Cantarell,sans-serif}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 var(--sans);-webkit-font-smoothing:antialiased}
.wrap{max-width:1320px;margin:0 auto;padding:20px 24px 40px}
header{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:18px}
.brand{display:flex;align-items:center;gap:10px;font:700 17px/1 var(--mono);letter-spacing:.14em}
.pulse{width:10px;height:10px;border-radius:50%;background:var(--green);animation:pulse 2s infinite}
.pulse.bad{background:var(--red);animation-name:pulsered}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(62,224,143,.55)}70%{box-shadow:0 0 0 10px rgba(62,224,143,0)}100%{box-shadow:0 0 0 0 rgba(62,224,143,0)}}
@keyframes pulsered{0%{box-shadow:0 0 0 0 rgba(255,95,95,.6)}70%{box-shadow:0 0 0 10px rgba(255,95,95,0)}100%{box-shadow:0 0 0 0 rgba(255,95,95,0)}}
.chip{font:12px var(--mono);color:var(--muted);background:var(--panel);border:1px solid var(--line);border-radius:999px;padding:5px 12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}
.chip.demo{color:var(--amber);border-color:rgba(246,185,59,.35)}
.spacer{flex:1}
.scanstat{font:12px var(--mono);color:var(--muted)}
button{font:600 13px var(--sans);color:var(--text);background:var(--panel2);border:1px solid var(--line2);border-radius:8px;padding:7px 14px;cursor:pointer}
button:hover{border-color:var(--green);color:var(--green)}
button.primary{background:var(--green);color:#03140b;border-color:var(--green)}
button.primary:hover{filter:brightness(1.08);color:#03140b}
button:disabled{opacity:.6;cursor:default}
.banner{display:none;gap:14px;align-items:flex-start;border-radius:12px;padding:14px 16px;margin-bottom:16px}
.banner.show{display:flex}
.banner.crit{background:var(--redbg);border:1px solid rgba(255,95,95,.45)}
.banner.warn{background:var(--amberbg);border:1px solid rgba(246,185,59,.4)}
.banner .bt{font-weight:700;margin-bottom:2px}
.banner.crit .bt{color:var(--red)} .banner.warn .bt{color:var(--amber)}
.banner .bd{font-size:13px;color:var(--text);opacity:.9}
.banner .bd code{font:12px var(--mono)}
.banner button{margin-left:auto;flex:none}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:16px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.stat .k{font-size:11.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.stat .v{font:700 28px/1.25 var(--mono);margin-top:2px}
.stat .v.g{color:var(--green)} .stat .v.a{color:var(--amber)} .stat .v.r{color:var(--red)}
.grid{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:16px;align-items:start}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.ph{display:flex;align-items:center;gap:10px;padding:12px 14px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.ph h2{font:600 12px var(--sans);text-transform:uppercase;letter-spacing:.09em;color:var(--muted);margin:0}
.tabs{display:flex;gap:2px;background:var(--bg);border:1px solid var(--line);border-radius:9px;padding:2px}
.tab{background:transparent;border:0;color:var(--muted);padding:5px 10px;font-weight:500;border-radius:7px}
.tab:hover{color:var(--text)}
.tab.on{background:var(--panel2);color:var(--text)}
.search{margin-left:auto;background:var(--bg);border:1px solid var(--line);border-radius:8px;color:var(--text);padding:6px 10px;font:13px var(--sans);width:200px;max-width:100%}
.search:focus{outline:none;border-color:var(--green)}
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{text-align:left;font:600 11px var(--sans);text-transform:uppercase;letter-spacing:.08em;color:var(--faint);padding:9px 12px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:middle;white-space:nowrap}
td.dev-td{white-space:normal;min-width:230px}
td.ports{white-space:normal;min-width:90px;max-width:190px}
.m-ip{display:none}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:rgba(255,255,255,.015)}
tr.off td>*{opacity:.42}
tr.new{background:linear-gradient(90deg,var(--redbg),transparent 70%)}
.mono{font-family:var(--mono);font-size:12.5px}
.dev{display:flex;align-items:center;gap:11px}
.ico{width:34px;height:34px;border-radius:9px;display:grid;place-items:center;background:var(--panel2);border:1px solid var(--line2);color:var(--muted);flex:none}
.ico.risk{color:var(--red);border-color:rgba(255,95,95,.4)}
.ico.gw{color:var(--blue)}
.ico svg{width:18px;height:18px}
.dname{font-weight:600}
.dsub{font-size:12px;color:var(--muted)}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;background:var(--faint)}
.dot.on{background:var(--green);box-shadow:0 0 8px rgba(62,224,143,.8)}
.tag{font:700 10px/1 var(--mono);padding:3px 6px;border-radius:4px;letter-spacing:.05em;margin-left:6px;vertical-align:2px}
.tag.new{color:var(--red);background:var(--redbg)} .tag.trusted{color:var(--green);background:var(--greenbg)}
.tag.you{color:var(--blue);background:var(--bluebg)} .tag.gw{color:var(--blue);background:var(--bluebg)}
.tag.priv{color:var(--amber);background:var(--amberbg)}
.port{display:inline-block;font:11.5px var(--mono);padding:1px 6px;border-radius:4px;background:var(--panel2);border:1px solid var(--line2);margin:1px 3px 1px 0}
.port.risk{color:var(--red);border-color:rgba(255,95,95,.45);background:var(--redbg)}
.muted{color:var(--faint)}
.acts{display:flex;gap:4px;justify-content:flex-end}
.acts button{padding:4px 9px;font-size:12px;font-weight:500;min-width:30px}
.acts button.ok{color:var(--green);border-color:rgba(62,224,143,.35)}
.empty{text-align:center;color:var(--muted);padding:40px 12px}
.events{max-height:640px;overflow:auto}
.ev{display:grid;grid-template-columns:3px 1fr;gap:11px;padding:10px 14px;border-bottom:1px solid var(--line)}
.ev:last-child{border-bottom:0}
.ev .bar{border-radius:3px;background:var(--faint)}
.ev.info .bar{background:var(--blue)} .ev.warn .bar{background:var(--amber)} .ev.crit .bar{background:var(--red)}
.ev .m{font-size:13px;word-break:break-word}
.ev.crit .m{color:var(--red);font-weight:600}
.ev .t{font:11px var(--mono);color:var(--faint);margin-top:2px}
footer{margin-top:22px;font-size:12px;color:var(--faint);text-align:center}
@media (max-width:1180px){.grid{grid-template-columns:minmax(0,1fr)}.events{max-height:none}}
@media (max-width:760px){.wrap{padding:16px}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.c-mac,.c-ip{display:none}.m-ip{display:inline}
thead{display:none}
tbody tr{display:grid;grid-template-columns:22px minmax(0,1fr) auto;align-items:center;border-bottom:1px solid var(--line);padding:4px 0}
tbody tr:last-child{border-bottom:0}
tbody td{border-bottom:0;padding:6px 10px}
td.dev-td{min-width:0;padding-left:4px}
td.ports{min-width:0;max-width:130px;text-align:right}
td.acts-td{grid-column:2/4;padding-top:0;padding-left:49px}
td.acts-td:has(.acts:empty){display:none}
.acts{justify-content:flex-start}
td.empty{grid-column:1/-1}
.search{width:100%;margin-left:0}.spacer{display:none}.stat .v{font-size:24px}.banner{flex-wrap:wrap}.banner button{margin-left:0}}
</style></head><body>
<div class="wrap">
<header>
  <div class="brand"><span class="pulse" id="pulse"></span>NETWATCH</div>
  <span class="chip" id="netchip">connecting…</span>
  <span class="chip demo" id="demochip" hidden>DEMO · simulated network</span>
  <span class="spacer"></span>
  <span class="scanstat" id="scanstat"></span>
  <button class="primary" id="scanbtn">Scan now</button>
</header>
<div class="banner crit" id="gwbanner"><div><div class="bt">Possible man-in-the-middle attack</div><div class="bd" id="gwtext"></div></div><button id="acceptgw">I replaced my router</button></div>
<div class="banner warn" id="dupbanner"><div><div class="bt">IP address conflict</div><div class="bd" id="duptext"></div></div></div>
<section class="stats">
  <div class="stat"><div class="k">Online now</div><div class="v g" id="s-online">–</div></div>
  <div class="stat"><div class="k">Known devices</div><div class="v" id="s-known">–</div></div>
  <div class="stat"><div class="k">Untrusted online</div><div class="v" id="s-untrusted">–</div></div>
  <div class="stat"><div class="k">Alerts · 24h</div><div class="v" id="s-alerts">–</div></div>
</section>
<div class="grid">
  <section class="panel">
    <div class="ph">
      <h2>Devices</h2>
      <div class="tabs" id="tabs">
        <button class="tab on" data-f="all">All</button><button class="tab" data-f="online">Online</button>
        <button class="tab" data-f="untrusted">Untrusted</button><button class="tab" data-f="risky">Risky</button>
      </div>
      <input class="search" id="search" placeholder="Search name, IP, MAC, vendor…" autocomplete="off">
    </div>
    <div class="tw"><table>
      <thead><tr><th></th><th>Device</th><th class="c-ip">IP</th><th class="c-mac">MAC</th><th>Open ports</th><th></th></tr></thead>
      <tbody id="devs"></tbody>
    </table></div>
  </section>
  <section class="panel">
    <div class="ph"><h2>Activity</h2></div>
    <div class="events" id="events"></div>
  </section>
</div>
<footer>NetWatch <span id="ver"></span> · only monitor networks you own or are allowed to monitor</footer>
</div>
<script nonce="__NONCE__">
"use strict";
const TOKEN = "__NETWATCH_TOKEN__";
let S = null, FILTER = "all", Q = "", OFFSET = 0, FAILS = 0;
const $ = s => document.querySelector(s);
const ICONS = {
  router:'<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h.01M11 16.5h.01M8 13 6.5 5M16 13l1.5-8"/>',
  phone:'<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18h2"/>',
  laptop:'<rect x="4" y="4.5" width="16" height="11" rx="1.5"/><path d="M2 19.5h20"/>',
  tv:'<rect x="2.5" y="4" width="19" height="13" rx="2"/><path d="M8 21h8M12 17v4"/>',
  speaker:'<rect x="6" y="2.5" width="12" height="19" rx="3"/><circle cx="12" cy="14" r="3.5"/><path d="M12 7h.01"/>',
  camera:'<circle cx="12" cy="10" r="6.5"/><circle cx="12" cy="10" r="2.2"/><path d="M8 21h8M12 16.5V21"/>',
  printer:'<path d="M7 9V3h10v6"/><rect x="3" y="9" width="18" height="8" rx="2"/><path d="M7 14h10v7H7z"/>',
  server:'<rect x="4" y="3" width="16" height="7" rx="1.5"/><rect x="4" y="14" width="16" height="7" rx="1.5"/><path d="M8 6.5h.01M8 17.5h.01"/>',
  chip:'<rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4"/>',
  unknown:'<circle cx="12" cy="12" r="9"/><path d="M9.6 9.5a2.5 2.5 0 1 1 3.4 2.3c-.6.3-1 .8-1 1.5v.4M12 17.3h.01"/>'
};
function el(tag, props, ...kids){
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})){
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v);
  }
  for (const c of kids.flat()){ if (c === null || c === undefined || c === false) continue; e.append(c.nodeType ? c : document.createTextNode(String(c))); }
  return e;
}
function icon(cat){
  const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  for (const [k, v] of Object.entries({viewBox:"0 0 24 24", fill:"none", stroke:"currentColor", "stroke-width":"1.8", "stroke-linecap":"round", "stroke-linejoin":"round"})) s.setAttribute(k, v);
  s.innerHTML = ICONS[cat] || ICONS.unknown;  // static markup only
  return s;
}
const tag = (cls, text) => el("span", {class: "tag " + cls}, text);
const now = () => Date.now() / 1000 + OFFSET;
function ago(ts){
  if (!ts) return "never";
  const s = Math.max(0, Math.round(now() - ts));
  if (s < 10) return "just now"; if (s < 60) return s + "s ago";
  const m = Math.round(s / 60); if (m < 60) return m + "m ago";
  const h = Math.round(m / 60); if (h < 48) return h + "h ago";
  return Math.round(h / 24) + "d ago";
}
async function api(path, body){
  const opt = {headers: {"X-NetWatch-Token": TOKEN}};
  if (body !== undefined){ opt.method = "POST"; opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
}
const isOnline = d => now() - (d.last_seen || 0) <= S.online_window;
const riskyPorts = d => (d.ports || []).filter(p => S.ports[p] && S.ports[p][1]);
const isNew = d => !d.trusted && !d.is_self && S.baseline_at && d.first_seen > S.baseline_at + 1 && now() - d.first_seen < 86400;
const ipNum = ip => (ip || "0.0.0.0").split(".").reduce((a, b) => a * 256 + (+b), 0);

function renderHeader(){
  const n = S.network || {};
  $("#netchip").textContent = n.iface ? `${n.iface} · ${n.ssid || "wired"} · ${n.subnet} · gw ${n.gateway || "?"}` : "detecting network…";
  $("#demochip").hidden = !S.demo;
  $("#ver").textContent = "v" + S.version;
  tick();
}
function tick(){
  if (!S) return;
  const sc = S.scan, st = $("#scanstat");
  if (FAILS > 1) st.textContent = "disconnected · is netwatch still running?";
  else if (sc.running) st.textContent = "scanning…";
  else if (sc.error) st.textContent = sc.error;
  else if (sc.last){ const nx = Math.max(0, Math.round((sc.next || 0) - now())); st.textContent = `scan #${sc.count} · ${ago(sc.last)} · next in ${nx}s`; }
  else st.textContent = "first scan running…";
}
function renderBanners(){
  const g = S.alerts.gateway, gb = $("#gwbanner");
  gb.classList.toggle("show", !!g);
  $("#pulse").classList.toggle("bad", !!g);
  if (g){
    const t = $("#gwtext"); t.replaceChildren();
    t.append("Your router ", el("code", null, g.gateway || ""), " normally has MAC ", el("code", null, g.expected || "?"),
      ", but ", el("code", null, g.seen.join(", ")), " is answering for it. Someone may be intercepting traffic on this network (ARP spoofing).");
  }
  const d = S.alerts.dup, db = $("#dupbanner");
  db.classList.toggle("show", !!d);
  if (d) $("#duptext").textContent = d.map(x => { const [ip, macs] = x.split("="); return `${ip} is answered by ${macs.split("/").join(" and ")}`; }).join(" · ");
}
function renderStats(){
  const on = S.devices.filter(isOnline);
  const untrusted = on.filter(d => !d.trusted && !d.is_self).length;
  const day = S.events.filter(e => e.level !== "info" && now() - e.ts < 86400);
  const crit = day.some(e => e.level === "crit");
  $("#s-online").textContent = on.length;
  $("#s-known").textContent = S.devices.length;
  const u = $("#s-untrusted"); u.textContent = untrusted; u.className = "v " + (untrusted ? "a" : "");
  const a = $("#s-alerts"); a.textContent = day.length; a.className = "v " + (crit ? "r" : day.length ? "a" : "");
}
function portsCell(d){
  if (d.ports === null) return el("span", {class: "muted", title: "Not checked yet"}, "–");
  if (!d.ports.length) return el("span", {class: "muted"}, "none");
  return d.ports.map(p => {
    const info = S.ports[p] || [String(p), null];
    return el("span", {class: "port" + (info[1] ? " risk" : ""), title: info[0] + (info[1] ? " · " + info[1] : "")}, String(p));
  });
}
async function act(d, action, extra){
  try { await api("/api/device", Object.assign({mac: d.mac, action}, extra || {})); } catch (e) { alert("Failed: " + e.message); }
  refresh();
}
function actions(d){
  if (d.is_self) return el("div", {class: "acts"});
  return el("div", {class: "acts"},
    el("button", {class: d.trusted ? "ok" : "", title: d.trusted ? "Click to untrust" : "Mark as one of your devices",
      onclick: () => act(d, d.trusted ? "untrust" : "trust")}, d.trusted ? "✓ Trusted" : "Trust"),
    el("button", {title: "Rename", "aria-label": "Rename", onclick: () => { const n = prompt("Name this device:", d.name || d.hostname || ""); if (n !== null) act(d, "rename", {name: n}); }}, "✎"),
    el("button", {title: "Forget (it will alert as new next time)", "aria-label": "Forget", onclick: () => { if (confirm("Forget " + (d.name || d.ip) + "? It will show up as a new device next time.")) act(d, "forget"); }}, "×"));
}
function renderDevices(){
  const tb = $("#devs"); tb.replaceChildren();
  let list = S.devices.slice().sort((a, b) => (b.is_gateway - a.is_gateway) || (ipNum(a.ip) - ipNum(b.ip)));
  if (FILTER === "online") list = list.filter(isOnline);
  if (FILTER === "untrusted") list = list.filter(d => !d.trusted && !d.is_self);
  if (FILTER === "risky") list = list.filter(d => riskyPorts(d).length);
  if (Q) list = list.filter(d => [d.name, d.hostname, d.ip, d.mac, d.vendor, d.type].join(" ").toLowerCase().includes(Q));
  if (!list.length){
    tb.append(el("tr", null, el("td", {colspan: 6, class: "empty"}, S.devices.length ? "No devices match." : "Waiting for the first scan…")));
    return;
  }
  for (const d of list){
    const on = isOnline(d), nw = isNew(d), rk = riskyPorts(d).length > 0;
    const title = d.name || d.hostname || (d.is_self ? "This computer" : "Unnamed device");
    const parts = [d.type];
    if (d.vendor && !/^(Unknown vendor|Private)/.test(d.vendor)) parts.push(d.vendor);
    if (!on) parts.push("seen " + ago(d.last_seen));
    tb.append(el("tr", {class: (on ? "" : "off ") + (nw ? "new" : "")},
      el("td", null, el("span", {class: "dot" + (on ? " on" : ""), title: on ? "Online" : "Offline · last seen " + ago(d.last_seen)})),
      el("td", {class: "dev-td"}, el("div", {class: "dev"},
        el("div", {class: "ico" + (rk ? " risk" : d.is_gateway ? " gw" : "")}, icon(d.cat)),
        el("div", null,
          el("div", {class: "dname", title: d.hostname ? "Hostname: " + d.hostname : null}, title, d.is_self ? tag("you", "YOU") : null, d.is_gateway ? tag("gw", "GATEWAY") : null,
             nw ? tag("new", "NEW") : null, d.trusted && !d.is_self && !d.is_gateway ? tag("trusted", "TRUSTED") : null),
          el("div", {class: "dsub"}, el("span", {class: "m-ip mono"}, d.ip + " · "), parts.join(" · "))))),
      el("td", {class: "mono c-ip"}, d.ip),
      el("td", {class: "mono c-mac", title: d.private ? "Randomized (private) MAC address" : null}, d.mac),
      el("td", {class: "ports"}, portsCell(d)),
      el("td", {class: "acts-td"}, actions(d))));
  }
}
function renderEvents(){
  const box = $("#events"); box.replaceChildren();
  if (!S.events.length){ box.append(el("div", {class: "empty"}, "Nothing yet.")); return; }
  for (const e of S.events){
    box.append(el("div", {class: "ev " + e.level}, el("div", {class: "bar"}),
      el("div", null, el("div", {class: "m"}, e.message), el("div", {class: "t"}, ago(e.ts) + (e.ip ? " · " + e.ip : "")))));
  }
}
async function refresh(){
  try {
    S = await api("/api/state");
    OFFSET = S.now - Date.now() / 1000; FAILS = 0;
    renderHeader(); renderBanners(); renderStats(); renderDevices(); renderEvents();
  } catch (e) { FAILS++; tick(); }
}
$("#tabs").addEventListener("click", e => {
  const b = e.target.closest(".tab"); if (!b) return;
  FILTER = b.dataset.f; document.querySelectorAll(".tab").forEach(t => t.classList.toggle("on", t === b)); renderDevices();
});
$("#search").addEventListener("input", e => { Q = e.target.value.trim().toLowerCase(); renderDevices(); });
$("#scanbtn").addEventListener("click", async e => {
  const b = e.target; b.disabled = true; b.textContent = "Scanning…";
  try { await api("/api/scan", {}); } catch (err) {}
  setTimeout(() => { b.disabled = false; b.textContent = "Scan now"; refresh(); }, 2500);
});
$("#acceptgw").addEventListener("click", async () => {
  if (!confirm("Only do this if you really replaced or reset your router. Accept the new router MAC?")) return;
  try { await api("/api/accept-gateway", {}); } catch (e) {}
  refresh();
});
refresh(); setInterval(refresh, 3000); setInterval(tick, 1000);
</script>
</body></html>
"""

if __name__ == "__main__":
    main()
