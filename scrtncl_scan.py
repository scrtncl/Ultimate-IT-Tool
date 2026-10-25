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

Safety:
  - Read-only. Nothing is changed on any device.
  - It only scans a private home or office address range (such as
    192.168.x.x), and only the one /24 block your computer is in
    (up to 254 addresses). It refuses anything else.
  - Only scan networks you own or have permission to manage.

Run it on its own with:   python scrtncl_scan.py      (or: py scrtncl_scan.py)
"""

import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import scrtncl_doctor as doctor

OS = platform.system()
FOLDER = os.path.dirname(os.path.abspath(__file__))
DEVICES_FILE = os.path.join(FOLDER, "scrtncl-devices.json")

MAX_HISTORY = 300          # most devices kept in the history file
NEW_DEVICE_DAYS = 7        # a device counts as new for this many days
IP_PATTERN = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
MAC_PATTERN = re.compile(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")


class ScanNotAllowed(Exception):
    """Raised when the network is not one scrtncl is willing to scan."""


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
    return load_history().get("last_report")


def days_since(iso_time, now):
    return (now - datetime.fromisoformat(iso_time)).total_seconds() / 86400


# ---------------------------------------------------------------
# The scan
# ---------------------------------------------------------------

def scan():
    """Scan the local network and return a report dictionary."""
    local_ip, network = get_network()
    gateway = doctor.get_gateway()

    replies = sweep(network)
    neighbors = {ip: mac for ip, mac in read_neighbors().items()
                 if ipaddress.ip_address(ip) in network
                 and ipaddress.ip_address(ip) != network.broadcast_address}

    addresses = set(replies) | set(neighbors) | {local_ip}
    with ThreadPoolExecutor(max_workers=16) as pool:
        names = dict(zip(sorted(addresses), pool.map(lookup_name, sorted(addresses))))
    names[local_ip] = socket.gethostname()

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
        record.update({
            "network": network_name,
            "ip": ip,
            "mac": mac,
            "hostname": names.get(ip) or record.get("hostname"),
            "kind": kind,
            "last_seen": now,
            "ping_ms": replies.get(ip),
            "private_mac": is_private_mac(mac) if mac else False,
        })
        history["devices"][device_id] = record

    devices = []
    for device_id, record in history["devices"].items():
        if record.get("network") != network_name:
            continue  # remembered from a different network
        online = device_id in seen_ids
        is_new = (not record.get("baseline")) and days_since(record["first_seen"], now_time) < NEW_DEVICE_DAYS
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
        "devices": devices,
    }
    history["scan_count"] += 1
    history["last_report"] = report
    save_history(history)
    return report


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
