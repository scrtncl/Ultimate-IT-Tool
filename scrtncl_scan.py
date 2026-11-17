"""
scrtncl engine, step 5: device scan.

Finds the devices on your local network. No router login is needed, so
it works on any router.

How it works:
  1. It pings every address in your network (for example 192.168.100.1
     to 192.168.100.254) so each device shows up in this computer's
     address table.
  2. It reads that table (the ARP table) to get each device's MAC address.
  3. It asks the network for each device's name, when the device shares it.
  4. It remembers devices between scans in scrtncl-devices.json, so it
     can show which ones are offline or new.
  4b. For each device that answered, it asks for the device's name in three
     ways (a normal name lookup, Bonjour/mDNS, and NetBIOS), and looks up
     who made it from its MAC address. If a name or maker points to a
     brand or kind of device, it is shown as a guess, never as a fact.
     The maker list is a file you download once (see load_oui below) and
     is read on this computer. No address is sent over the internet.
  5. You can give a device your own name, put it in a group, mark it as
     known, and ping it. These choices are saved in scrtncl-devices.json
     on this computer and never change the device itself.

Safety:
  - Read-only. Nothing is changed on any device.
  - It only scans a private home or office address range (such as
    192.168.x.x), and only the one /24 block your computer is in
    (up to 254 addresses). It refuses anything else.
  - Only scan networks you own or have permission to manage.

Run it on its own with:   python scrtncl_scan.py      (or: py scrtncl_scan.py)
"""

import csv
import ipaddress
import json
import os
import platform
import re
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import scrtncl_doctor as doctor

OS = platform.system()
FOLDER = os.path.dirname(os.path.abspath(__file__))
DEVICES_FILE = os.path.join(FOLDER, "scrtncl-devices.json")

MAX_HISTORY = 300          # most devices kept in the history file
NEW_DEVICE_DAYS = 7        # a device counts as new for this many days
MAX_NAME = 40              # longest custom name
PING_COUNT = 4             # pings sent by "Ping this device"
GROUPS = ["Computers", "Phones and tablets", "Servers and storage",
          "TVs and media", "Smart home (IoT)", "Guests", "Other"]
history_lock = threading.Lock()   # one change to the saved list at a time
IP_PATTERN = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
MAC_PATTERN = re.compile(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")


class ScanNotAllowed(Exception):
    """Raised when the network is not one scrtncl is willing to scan."""


class DeviceError(Exception):
    """Raised when a device request is not valid."""


# ---------------------------------------------------------------
# Finding the network to scan
# ---------------------------------------------------------------

def get_network():
    """Return (local_ip, network) for the /24 block this computer is in."""
    local_ip = doctor.get_local_ip()
    if not local_ip:
        raise ScanNotAllowed("This computer has no network address, so there is nothing to scan.")
    address = ipaddress.ip_address(local_ip)
    if address.is_loopback or address.is_link_local or not address.is_private:
        raise ScanNotAllowed(
            "Your address (" + local_ip + ") is not in a private home or office range, "
            "so scrtncl will not scan it.")
    network = ipaddress.ip_network(local_ip + "/24", strict=False)
    return local_ip, network


# ---------------------------------------------------------------
# Ping sweep, ARP table, names
# ---------------------------------------------------------------

def ping_once(ip):
    """Ping one address. Returns the time in ms, or None if there was no reply."""
    if OS == "Windows":
        command = ["ping", "-n", "1", "-w", "700", ip]
    elif OS == "Darwin":
        command = ["ping", "-c", "1", "-W", "700", ip]
    else:
        command = ["ping", "-c", "1", "-W", "1", ip]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return None
    output = result.stdout.lower()
    # A real reply always includes a TTL. This skips "host unreachable" messages.
    if result.returncode != 0 or "ttl" not in output:
        return None
    match = re.search(r"time[=<]\s*([\d.]+)", output)
    return float(match.group(1)) if match else 0.0


def sweep(network):
    """Ping every host address in the network. Returns {ip: milliseconds}."""
    hosts = [str(host) for host in network.hosts()]
    with ThreadPoolExecutor(max_workers=64) as pool:
        results = list(pool.map(ping_once, hosts))
    return {ip: ms for ip, ms in zip(hosts, results) if ms is not None}


def normalize_mac(text):
    parts = re.split(r"[:-]", text)
    return ":".join(part.zfill(2) for part in parts).upper()


def parse_neighbors(output):
    """Pull (ip -> MAC) pairs out of 'arp -a' or 'ip neigh' output."""
    entries = {}
    for line in output.splitlines():
        ip_match = IP_PATTERN.search(line)
        mac_match = MAC_PATTERN.search(line)
        if not ip_match or not mac_match:
            continue
        mac = normalize_mac(mac_match.group(1))
        if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00") or mac.startswith("01:00:5E"):
            continue
        entries[ip_match.group(1)] = mac
    return entries


def read_neighbors():
    """Read this computer's address table."""
    for command in (["arp", "-a"], ["ip", "neigh"]):
        try:
            output = subprocess.run(command, capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        entries = parse_neighbors(output)
        if entries:
            return entries
    return {}


def lookup_name(ip):
    """Ask the network for a device's name. Many devices do not share one."""
    finished, value = doctor.run_with_timeout(lambda: socket.gethostbyaddr(ip)[0], 2)
    if finished and value:
        return value
    return None


def is_private_mac(mac):
    """Phones and laptops often use a made-up MAC address to protect privacy."""
    return bool(int(mac[:2], 16) & 2)


# ---------------------------------------------------------------
# Names, makers, and a best guess
# ---------------------------------------------------------------

MDNS_PORT = 5353
NETBIOS_PORT = 137
NAME_TIMEOUT = 1.0
# Free list from the IEEE, saved in this folder: https://standards-oui.ieee.org/oui/oui.csv
OUI_FILES = ["oui.csv", "oui28.csv", "oui36.csv"]
_oui_table = None


def read_dns_name(data, offset):
    """Read a name from a DNS-style packet. Returns (name, offset after it)."""
    labels = []
    end = None
    jumps = 0
    while True:
        if offset >= len(data):
            raise ValueError("packet too short")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("packet too short")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            jumps += 1
            if jumps > 10:
                raise ValueError("too many jumps")
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), (end if end is not None else offset)


def udp_ask(ip, port, packet, timeout=NAME_TIMEOUT):
    """Send one small UDP question to one device and return its answer, or None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(packet, (ip, port))
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            data, source = sock.recvfrom(2048)
            if source[0] == ip:
                return data
    except OSError:
        return None
    finally:
        sock.close()


def build_mdns_query(ip):
    """A Bonjour question: what is the name for this address?"""
    reverse = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in reverse.split("."))
    return struct.pack(">HHHHHH", 0x5C01, 0, 1, 0, 0, 0) + question + b"\x00" + struct.pack(">HH", 12, 1)


def parse_mdns_reply(data):
    """Pull the first name out of a Bonjour answer, or None."""
    try:
        question_count, answer_count = struct.unpack(">HH", data[4:8])
        offset = 12
        for _ in range(question_count):
            _, offset = read_dns_name(data, offset)
            offset += 4
        for _ in range(answer_count):
            _, offset = read_dns_name(data, offset)
            record_type, _, _, length = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            if record_type == 12:
                name, _ = read_dns_name(data, offset)
                return name
            offset += length
    except (ValueError, struct.error):
        pass
    return None


def mdns_name(ip, port=MDNS_PORT, timeout=NAME_TIMEOUT):
    data = udp_ask(ip, port, build_mdns_query(ip), timeout)
    return parse_mdns_reply(data) if data else None


def build_netbios_query():
    """A NetBIOS question: what names do you have? (Windows computers answer this.)"""
    return (struct.pack(">HHHHHH", 0x5C02, 0, 1, 0, 0, 0) + b"\x20" + b"CK" + b"A" * 30 + b"\x00" +
            struct.pack(">HH", 0x0021, 0x0001))


def parse_netbios_reply(data):
    """Pull the computer name out of a NetBIOS answer, or None."""
    try:
        answer_count = struct.unpack(">H", data[6:8])[0]
        if answer_count < 1:
            return None
        _, offset = read_dns_name(data, 12)
        offset += 10  # type, class, time to live, data length
        count = data[offset]
        offset += 1
        for _ in range(count):
            entry = data[offset:offset + 18]
            offset += 18
            if len(entry) < 18:
                break
            name = entry[:15].decode("ascii", "replace").strip()
            flags = int.from_bytes(entry[16:18], "big")
            if entry[15] == 0 and not flags & 0x8000 and name:
                return name
    except (ValueError, IndexError, struct.error):
        pass
    return None


def netbios_name(ip, port=NETBIOS_PORT, timeout=NAME_TIMEOUT):
    data = udp_ask(ip, port, build_netbios_query(), timeout)
    return parse_netbios_reply(data) if data else None


def clean_device_name(name):
    """Tidy a name a device shared. Returns None if there is nothing useful."""
    if not name:
        return None
    name = "".join(ch for ch in name if ch.isprintable()).strip().rstrip(".")
    for ending in (".local", ".lan", ".home", ".localdomain"):
        if name.lower().endswith(ending):
            name = name[:-len(ending)]
    name = name[:63]
    if not name or re.fullmatch(r"[0-9.\-]+", name):
        return None  # empty, or only the address written out
    return name


def find_name(ip):
    """Ask a device for its name. Returns (name, how) or (None, None)."""
    finished, value = doctor.run_with_timeout(lambda: socket.gethostbyaddr(ip)[0], 2)
    name = clean_device_name(value) if finished else None
    if name:
        return name, "a normal name lookup"
    name = clean_device_name(mdns_name(ip))
    if name:
        return name, "Bonjour (mDNS)"
    name = clean_device_name(netbios_name(ip))
    if name:
        return name, "NetBIOS"
    return None, None


def load_oui():
    """Read the maker list from this folder, if it was downloaded. Returns a dictionary."""
    global _oui_table
    if _oui_table is not None:
        return _oui_table
    table = {}
    for filename in OUI_FILES:
        try:
            with open(os.path.join(FOLDER, filename), encoding="utf-8-sig", newline="") as file:
                for row in csv.reader(file):
                    if len(row) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6,9}", row[1].strip()):
                        table[row[1].strip().upper()] = row[2].strip()
        except (OSError, UnicodeDecodeError, csv.Error):
            continue
    if table:
        _oui_table = table
    return table


def maker_of(mac):
    """Who made the network hardware. Not possible for private (made-up) addresses."""
    if not mac or is_private_mac(mac):
        return None
    table = load_oui()
    digits = mac.replace(":", "").upper()
    for length in (9, 7, 6):
        if digits[:length] in table:
            return table[digits[:length]]
    return None


def word(pattern):
    return re.compile(r"(?<![a-z0-9])(?:" + pattern + r")(?![a-z])", re.IGNORECASE)


# (pattern, brand, model). A model written as None is taken from the name itself.
GUESS_RULES = [
    (word(r"iphone"), "Apple", "iPhone"),
    (word(r"ipad"), "Apple", "iPad"),
    (word(r"macbook|imac|mac-?mini|mac-?studio"), "Apple", "Mac"),
    (word(r"apple-?watch"), "Apple", "Watch"),
    (word(r"apple-?tv"), "Apple", "Apple TV"),
    (word(r"galaxy[-_ ]?(?:s\d+\w*|a\d+\w*|z[-_ ]?(?:flip|fold)\d*|note\d+\w*)"), "Samsung", None),
    (word(r"galaxy|samsung"), "Samsung", "device"),
    (word(r"pixel[-_ ]?\d+\w*"), "Google", "Pixel"),
    (word(r"redmi|xiaomi|poco"), "Xiaomi", "phone"),
    (word(r"oppo"), "Oppo", "phone"),
    (word(r"vivo"), "vivo", "phone"),
    (word(r"realme"), "realme", "phone"),
    (word(r"huawei|honor"), "Huawei/Honor", "phone"),
    (word(r"oneplus"), "OnePlus", "phone"),
    (word(r"android"), None, "Android device"),
    (word(r"desktop-\w+|laptop-\w+"), None, "Windows PC"),
    (word(r"xbox"), "Microsoft", "Xbox"),
    (word(r"playstation|ps[45]"), "Sony", "PlayStation"),
    (word(r"chromecast"), "Google", "Chromecast"),
    (word(r"roku"), "Roku", "device"),
    (word(r"fire-?tv|kindle|echo-?\w*|alexa"), "Amazon", "device"),
    (word(r"printer|laserjet|officejet|deskjet"), None, "Printer"),
]


def short_maker(maker):
    """Trim 'Inc.', 'Co., Ltd.' and similar from a maker name."""
    for _ in range(3):
        maker = re.sub(r",?\s*(inc\.?|co\.?,?\s*ltd\.?|ltd\.?|corporation|corp\.?|llc|gmbh)\s*$", "", maker,
                       flags=re.IGNORECASE).strip()
    return maker


def guess_device(hostname, maker):
    """A best guess at the kind of device. Returns (label, basis) or (None, None).

    basis is "name" when the device's own name points to it, or "maker" when only
    the maker is known. This is a guess: names can be changed, and a maker only
    says who built the network hardware.
    """
    if hostname:
        for pattern, brand, model in GUESS_RULES:
            found = pattern.search(hostname)
            if found:
                if model is None:
                    model = re.sub(r"[-_ ]+", " ", found.group(0)).title()
                label = " ".join(part for part in (brand, model) if part)
                return label, "name"
    if maker:
        return short_maker(maker), "maker"
    return None, None


# ---------------------------------------------------------------
# History
# ---------------------------------------------------------------

def load_history():
    try:
        with open(DEVICES_FILE, encoding="utf-8") as file:
            data = json.load(file)
        if isinstance(data.get("devices"), dict):
            return data
    except (OSError, ValueError):
        pass
    return {"scan_count": 0, "devices": {}, "last_report": None}


def save_history(history):
    # Keep the most recently seen devices if the list grows too long.
    devices = history["devices"]
    if len(devices) > MAX_HISTORY:
        newest = sorted(devices.items(), key=lambda item: item[1]["last_seen"], reverse=True)
        history["devices"] = dict(newest[:MAX_HISTORY])
    with open(DEVICES_FILE, "w", encoding="utf-8") as file:
        json.dump(history, file, indent=2)


def load_last_report():
    report = load_history().get("last_report")
    if report and isinstance(report.get("devices"), list):
        now_time = datetime.now()
        report["devices"] = [d for d in report["devices"]
                             if not (d.get("status") == "offline" and is_stale_private(d, now_time))]
    return report


def days_since(iso_time, now):
    return (now - datetime.fromisoformat(iso_time)).total_seconds() / 86400


def compute_is_new(record, now_time):
    """New = not in the first scan, seen recently, and not marked as known."""
    return ((not record.get("baseline")) and (not record.get("known"))
            and days_since(record["first_seen"], now_time) < NEW_DEVICE_DAYS)


def is_stale_private(record, now_time):
    """A device is an abandoned ghost if it used a randomized private MAC, has no
    custom name, is not marked as known, and was last seen more than 24 hours ago."""
    if not record.get("private_mac"):
        return False
    if record.get("custom_name") or record.get("known"):
        return False
    try:
        return days_since(record.get("last_seen", ""), now_time) >= 1.0
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------
# The scan
# ---------------------------------------------------------------

def record_scan(local_ip, network, gateway, replies, neighbors, addresses, names, sources=None):
    """Update the saved device list with this scan and build the report."""
    with history_lock:
        history = load_history()
        first_scan = history["scan_count"] == 0
        now_time = datetime.now()
        now = now_time.isoformat(timespec="seconds")
        network_name = str(network)
        seen_ids = set()

        for ip in addresses:
            mac = neighbors.get(ip)
            if ip == local_ip:
                device_id = "this-computer"
            elif mac:
                device_id = mac
            else:
                device_id = "ip-" + ip
            seen_ids.add(device_id)

            if ip == gateway:
                kind = "Router (gateway)"
            elif ip == local_ip:
                kind = "This computer"
            else:
                kind = "Unknown"

            record = history["devices"].get(device_id)
            if record is None or record.get("network") != network_name:
                record = {"first_seen": now, "baseline": first_scan}
            hostname = names.get(ip) or record.get("hostname")
            maker = maker_of(mac)
            guess, guess_basis = guess_device(hostname, maker)
            record.update({
                "network": network_name,
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "name_source": ((sources or {}).get(ip) if names.get(ip) else record.get("name_source")),
                "maker": maker,
                "guess": guess,
                "guess_basis": guess_basis,
                "kind": kind,
                "last_seen": now,
                "ping_ms": replies.get(ip),
                "private_mac": is_private_mac(mac) if mac else False,
            })
            history["devices"][device_id] = record

        # Prune abandoned ghost devices that used randomized private MACs (>24h stale)
        stale_ids = [dev_id for dev_id, rec in history["devices"].items()
                     if dev_id not in seen_ids and is_stale_private(rec, now_time)]
        for dev_id in stale_ids:
            del history["devices"][dev_id]

        devices = []
        for device_id, record in history["devices"].items():
            if record.get("network") != network_name:
                continue  # remembered from a different network
            online = device_id in seen_ids
            is_new = compute_is_new(record, now_time)
            devices.append({
                "id": device_id,
                "hostname": record.get("hostname"),
                "kind": record["kind"],
                "ip": record["ip"],
                "mac": record.get("mac"),
                "status": "online" if online else "offline",
                "first_seen": record["first_seen"],
                "last_seen": record["last_seen"],
                "ping_ms": record.get("ping_ms") if online else None,
                "private_mac": record.get("private_mac", False),
                "is_new": is_new,
                "custom_name": record.get("custom_name"),
                "group": record.get("group"),
                "known": bool(record.get("known")),
                "name_source": record.get("name_source"),
                "maker": record.get("maker"),
                "guess": record.get("guess"),
                "guess_basis": record.get("guess_basis"),
            })

        def sort_key(device):
            rank = 0 if device["kind"].startswith("Router") else 1 if device["kind"] == "This computer" else 2
            return (device["status"] == "offline", rank, ipaddress.ip_address(device["ip"]))

        devices.sort(key=sort_key)

        report = {
            "time": now,
            "network": network_name,
            "gateway": gateway,
            "local_ip": local_ip,
            "first_scan": first_scan,
            "maker_list_loaded": bool(load_oui()),
            "devices": devices,
        }
        history["scan_count"] += 1
        history["last_report"] = report
        save_history(history)
        return report


def scan():
    """Scan the local network and return a report dictionary."""
    local_ip, network = get_network()
    gateway = doctor.get_gateway()

    replies = sweep(network)
    neighbors = {ip: mac for ip, mac in read_neighbors().items()
                 if ipaddress.ip_address(ip) in network
                 and ipaddress.ip_address(ip) != network.broadcast_address}

    addresses = set(replies) | set(neighbors) | {local_ip}
    ordered = sorted(addresses)
    with ThreadPoolExecutor(max_workers=16) as pool:
        found = list(pool.map(find_name, ordered))
    names = {ip: pair[0] for ip, pair in zip(ordered, found)}
    sources = {ip: pair[1] for ip, pair in zip(ordered, found)}
    names[local_ip] = socket.gethostname()
    sources[local_ip] = "this computer"

    return record_scan(local_ip, network, gateway, replies, neighbors, addresses, names, sources)


# ---------------------------------------------------------------
# Naming, grouping, marking as known, and pinging one device
# ---------------------------------------------------------------

def clean_name(name):
    """Check a custom name. Returns the cleaned name, or None for 'no name'."""
    if name is None:
        return None
    if not isinstance(name, str):
        raise DeviceError("The name must be text.")
    name = "".join(ch for ch in name if ch.isprintable()).strip()
    if len(name) > MAX_NAME:
        raise DeviceError("The name can be at most " + str(MAX_NAME) + " characters.")
    return name or None


def update_device(device_id, name, group, known):
    """Save a custom name, a group, and the known flag for one device."""
    if not isinstance(device_id, str) or not device_id:
        raise DeviceError("No device was chosen.")
    name = clean_name(name)
    if group in ("", None):
        group = None
    elif group not in GROUPS:
        raise DeviceError("That group is not one of the choices.")
    if not isinstance(known, bool):
        raise DeviceError("Known must be true or false.")

    with history_lock:
        history = load_history()
        record = history["devices"].get(device_id)
        if record is None:
            raise DeviceError("That device is not in the saved list. Scan the network again.")
        for key, value in (("custom_name", name), ("group", group)):
            if value is None:
                record.pop(key, None)
            else:
                record[key] = value
        record["known"] = known

        # Keep the saved report in step, so the page needs no new scan.
        updated = None
        report = history.get("last_report")
        if report:
            for device in report["devices"]:
                if device["id"] == device_id:
                    device["custom_name"] = name
                    device["group"] = group
                    device["known"] = known
                    device["is_new"] = compute_is_new(record, datetime.now())
                    updated = device
        save_history(history)
    return updated or {"id": device_id, "custom_name": name, "group": group, "known": known}


def ping_device(device_id):
    """Ping one saved device a few times. Read-only."""
    if not isinstance(device_id, str) or not device_id:
        raise DeviceError("No device was chosen.")
    record = load_history()["devices"].get(device_id)
    if record is None:
        raise DeviceError("That device is not in the saved list. Scan the network again.")
    try:
        address = ipaddress.ip_address(record["ip"])
    except (KeyError, ValueError):
        raise DeviceError("That device has no usable address.")
    _, network = get_network()
    if not address.is_private or address not in network:
        raise DeviceError("That address is not on your current network, so it will not be pinged.")

    times = [ping_once(record["ip"]) for _ in range(PING_COUNT)]
    replies = [t for t in times if t is not None]
    return {
        "ip": record["ip"],
        "sent": PING_COUNT,
        "received": len(replies),
        "loss_percent": round(100 * (PING_COUNT - len(replies)) / PING_COUNT),
        "min_ms": min(replies) if replies else None,
        "avg_ms": round(sum(replies) / len(replies), 1) if replies else None,
        "max_ms": max(replies) if replies else None,
    }


# ---------------------------------------------------------------
# Free-form ping and traceroute (from the dashboard tool form)
# ---------------------------------------------------------------

HOST_MAX = 253          # longest host or IP string accepted
PING_MAX_COUNT = 20     # upper bound on packets the user may request


def _resolve_host(host):
    """Return the string to pass to system tools after basic validation.
    Accepts a bare IPv4/IPv6 address or a hostname (letters, digits, hyphens,
    dots).  Raises DeviceError for anything else."""
    host = host.strip()
    if not host or len(host) > HOST_MAX:
        raise DeviceError("Please type a host name or IP address.")
    # Try as a bare IP first
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    # Hostname: allow letters, digits, hyphens, dots only
    if not re.match(r"^[A-Za-z0-9.\-]+$", host):
        raise DeviceError("The host name contains characters that are not allowed.")
    return host


def ping_host(host, count=4):
    """Ping a freely typed host or IP address. Returns a summary dict."""
    target = _resolve_host(host)
    count = max(1, min(int(count), PING_MAX_COUNT))
    if OS == "Windows":
        command = ["ping", "-n", str(count), "-w", "2000", target]
    elif OS == "Darwin":
        command = ["ping", "-c", str(count), "-W", "2000", target]
    else:
        command = ["ping", "-c", str(count), "-W", "2", target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=count * 4 + 5)
    except (OSError, subprocess.SubprocessError) as error:
        raise DeviceError("ping could not run: " + str(error))
    output = result.stdout
    times = [float(m) for m in re.findall(r"time[=<]\s*([\d.]+)", output, re.IGNORECASE)]
    received = len(times)
    return {
        "tool": "ping",
        "host": target,
        "sent": count,
        "received": received,
        "loss_percent": round(100 * (count - received) / count),
        "min_ms": round(min(times), 1) if times else None,
        "avg_ms": round(sum(times) / len(times), 1) if times else None,
        "max_ms": round(max(times), 1) if times else None,
        "raw": output.strip(),
    }


def traceroute_host(host):
    """Run a traceroute to a freely typed host or IP. Returns raw output."""
    target = _resolve_host(host)
    if OS == "Windows":
        command = ["tracert", "-d", "-h", "20", "-w", "1000", target]
    elif OS == "Darwin":
        command = ["traceroute", "-n", "-m", "20", "-w", "2", target]
    else:
        command = ["traceroute", "-n", "-m", "20", "-w", "2", target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.SubprocessError) as error:
        raise DeviceError("traceroute could not run: " + str(error))
    return {
        "tool": "traceroute",
        "host": target,
        "raw": result.stdout.strip() or result.stderr.strip(),
    }


PORT_SCAN_MAX = 1000        # largest range allowed in one scan
PORT_SCAN_WORKERS = 100     # concurrent connection attempts
PORT_SCAN_TIMEOUT = 0.5     # seconds per port


def _resolve_private_ip(host):
    """Resolve host to an IP and confirm it is in a private range.
    Raises DeviceError if the address is public or cannot be resolved."""
    target = _resolve_host(host)
    try:
        ip_str = socket.gethostbyname(target)
        address = ipaddress.ip_address(ip_str)
    except (OSError, ValueError) as error:
        raise DeviceError("Could not resolve \"" + target + "\": " + str(error))
    if not address.is_private:
        raise DeviceError(
            "Port scanning is only allowed on private (local) addresses. "
            "\"" + ip_str + "\" is a public address.")
    return ip_str


def _probe_tcp_port(args):
    """Try a TCP connection to (ip, port). Returns port if open, else None."""
    ip, port = args
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(PORT_SCAN_TIMEOUT)
            if sock.connect_ex((ip, port)) == 0:
                return port
    except OSError:
        pass
    return None


WELL_KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3389: "RDP", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}


def port_scan_host(host, start, end):
    """TCP-connect scan a private host across a port range.
    Returns a list of open ports with well-known service labels."""
    start = max(1, min(int(start), 65535))
    end   = max(1, min(int(end),   65535))
    if start > end:
        start, end = end, start
    count = end - start + 1
    if count > PORT_SCAN_MAX:
        raise DeviceError(
            "That range covers " + str(count) + " ports. "
            "Please scan at most " + str(PORT_SCAN_MAX) + " ports at a time.")
    ip = _resolve_private_ip(host)
    pairs = [(ip, port) for port in range(start, end + 1)]
    with ThreadPoolExecutor(max_workers=PORT_SCAN_WORKERS) as pool:
        results = list(pool.map(_probe_tcp_port, pairs))
    open_ports = [
        {"port": p, "service": WELL_KNOWN_PORTS.get(p, "")}
        for p in results if p is not None
    ]
    return {
        "host": ip,
        "start": start,
        "end": end,
        "scanned": count,
        "open": open_ports,
    }


# ---------------------------------------------------------------
# Running it on its own
# ---------------------------------------------------------------

def main():
    print("scrtncl device scan (read-only)")
    print("Scanning your network. This takes about 10 to 30 seconds.\n")
    try:
        report = scan()
    except ScanNotAllowed as error:
        print("Not scanned: " + str(error))
        return

    print("Network " + report["network"] + ", scanned at " + report["time"] + "\n")
    for device in report["devices"]:
        flags = []
        if device["is_new"]:
            flags.append("NEW")
        if device["private_mac"]:
            flags.append("private MAC")
        if device.get("guess"):
            flags.append(("likely " if device["guess_basis"] == "name" else "made by ") + device["guess"])
        print(device["ip"].ljust(16) + (device["mac"] or "-").ljust(19) +
              device["status"].ljust(9) + (device["hostname"] or "(no name shared)") +
              ("  [" + ", ".join(flags) + "]" if flags else ""))

    online = sum(1 for d in report["devices"] if d["status"] == "online")
    print("\n" + str(online) + " online, " + str(len(report["devices"]) - online) + " offline.")
    if report["first_scan"]:
        print("This was the first scan. Devices found now are the baseline; "
              "devices that appear later will be flagged as new.")
    print("Saved to scrtncl-devices.json")


if __name__ == "__main__":
    main()
