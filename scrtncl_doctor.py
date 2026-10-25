"""
scrtncl engine, step 1: local Network Doctor.

Runs read-only checks on this computer's connection, prints a report,
and saves the same report to scrtncl-results.json.

Uses only the Python standard library. Nothing is changed on your
computer or router. The only traffic it sends is:
  - ping to your gateway (router)
  - connections to the public servers 1.1.1.1 and 8.8.8.8
  - DNS lookups and one HTTPS request to example.com

Run it with:   python scrtncl_doctor.py      (or: py scrtncl_doctor.py)
"""

import json
import os
import platform
import random
import re
import socket
import struct
import subprocess
import threading
import time
import urllib.request
from datetime import datetime

OS = platform.system()  # "Windows", "Linux" or "Darwin" (macOS)

REFERENCE_SERVERS = ["1.1.1.1", "8.8.8.8"]
TEST_NAMES = ["example.com", "wikipedia.org"]
HTTPS_TEST_URL = "https://example.com"
SLOW_ROUTER_MS = 20  # a router on your own network should answer faster than this


# ---------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------

def run_with_timeout(function, seconds):
    """Run function() and give up after `seconds`. Returns (finished, value)."""
    box = {}

    def target():
        try:
            box["value"] = function()
        except Exception as error:
            box["error"] = error

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive() or "error" in box:
        return False, None
    return True, box.get("value")


def get_local_ip():
    """Find this computer's main IPv4 address. No traffic is sent."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("1.1.1.1", 80))  # UDP connect only picks a route
        address = sock.getsockname()[0]
        sock.close()
        return address
    except OSError:
        return None


def get_gateway():
    """Find the default gateway (your router's address)."""
    try:
        if OS == "Windows":
            output = subprocess.run(
                ["route", "print", "-4", "0.0.0.0"],
                capture_output=True, text=True, timeout=5
            ).stdout
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    return parts[2]
        elif OS == "Darwin":
            output = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=5
            ).stdout
            match = re.search(r"gateway:\s*(\S+)", output)
            if match:
                return match.group(1)
        else:
            output = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            ).stdout
            match = re.search(r"default via (\S+)", output)
            if match:
                return match.group(1)
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def ping(host, count=3):
    """Ping a host. Returns (packets_received, count, average_ms or None)."""
    received = 0
    times = []
    for _ in range(count):
        if OS == "Windows":
            command = ["ping", "-n", "1", "-w", "1000", host]
        else:
            command = ["ping", "-c", "1", host]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0:
            received += 1
            match = re.search(r"time[=<]\s*([\d.]+)", result.stdout)
            if match:
                times.append(float(match.group(1)))
    average = round(sum(times) / len(times), 1) if times else None
    return received, count, average


def tcp_connect(host, port, timeout=2):
    """Try to open a TCP connection. Returns milliseconds, or None if it failed."""
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return round((time.time() - start) * 1000)
    except OSError:
        return None


def system_dns_lookup(name):
    """Look up a name using the DNS server this computer is set to use."""
    finished, value = run_with_timeout(lambda: socket.getaddrinfo(name, 443), 3)
    return finished and bool(value)


def direct_dns_query(server, name, timeout=2):
    """Ask one specific DNS server about a name. Returns True if it answered."""
    query_id = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    question += b"\x00" + struct.pack(">HH", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(header + question, (server, 53))
        data, _ = sock.recvfrom(512)
    except OSError:
        return False
    finally:
        sock.close()
    if len(data) < 12:
        return False
    reply_id, flags = struct.unpack(">HH", data[:4])
    answers = struct.unpack(">H", data[6:8])[0]
    return reply_id == query_id and (flags & 0xF) == 0 and answers > 0


def https_check(url, timeout=5):
    """Fetch a web page over HTTPS. Returns True if it loaded."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return 200 <= response.status < 400
    except Exception:
        return False


# ---------------------------------------------------------------
# The checks. Each returns a stage: name, status, detail.
# Status is one of: pass, fail, warn, skip
# ---------------------------------------------------------------

def stage(name, status, detail):
    return {"name": name, "status": status, "detail": detail}


def run_checks():
    stages = []
    facts = {}

    # 1. Physical and link
    stages.append(stage(
        "Physical and link", "skip",
        "Wi-Fi signal and link speed are added in a later step."
    ))

    # 2. IP configuration
    local_ip = get_local_ip()
    gateway = get_gateway()
    facts["local_ip"] = local_ip
    facts["gateway"] = gateway
    if local_ip and gateway:
        stages.append(stage("IP configuration", "pass",
                            "Address " + local_ip + ", gateway " + gateway + "."))
    elif local_ip:
        stages.append(stage("IP configuration", "warn",
                            "Address " + local_ip + ", but no gateway was found."))
    else:
        stages.append(stage("IP configuration", "fail",
                            "No usable network address was found."))

    # 3. Local gateway
    if gateway:
        received, sent, average = ping(gateway)
        facts["gateway_received"] = received
        facts["gateway_sent"] = sent
        facts["gateway_avg"] = average
        if received == sent and average is not None and average > SLOW_ROUTER_MS:
            stages.append(stage("Local gateway", "warn",
                                "Router replied to all " + str(sent) + " pings, but slowly: average " +
                                str(average) + " ms. A router on your own network should answer in a few milliseconds."))
        elif received == sent:
            timing = ", average " + str(average) + " ms" if average is not None else ""
            stages.append(stage("Local gateway", "pass",
                                "Router replied to " + str(received) + " of " + str(sent) +
                                " pings" + timing + "."))
        elif received > 0:
            stages.append(stage("Local gateway", "warn",
                                "Router replied to only " + str(received) + " of " + str(sent) +
                                " pings. Some packets are being lost."))
        else:
            stages.append(stage("Local gateway", "warn",
                                "Router did not answer pings. Some routers block pings on purpose."))
    else:
        facts["gateway_received"] = 0
        facts["gateway_sent"] = 0
        facts["gateway_avg"] = None
        stages.append(stage("Local gateway", "skip", "No gateway to test."))

    # 4. External connectivity (TCP is used because pings are often blocked)
    reachable = []
    connect_times = []
    for server in REFERENCE_SERVERS:
        milliseconds = tcp_connect(server, 53)
        if milliseconds is not None:
            connect_times.append(milliseconds)
            reachable.append(server + " (" + str(milliseconds) + " ms)")
    facts["external_ok"] = len(reachable) > 0
    facts["internet_ms"] = min(connect_times) if connect_times else None
    if reachable:
        stages.append(stage("External connectivity", "pass",
                            "Reached " + ", ".join(reachable) + "."))
    else:
        stages.append(stage("External connectivity", "fail",
                            "Could not reach any public test server."))

    # 5. DNS resolution
    system_ok = 0
    dns_times = []
    for name in TEST_NAMES:
        started = time.time()
        if system_dns_lookup(name):
            system_ok += 1
            dns_times.append((time.time() - started) * 1000)
    facts["dns_ms"] = round(sum(dns_times) / len(dns_times)) if dns_times else None
    reference_ok = sum(1 for name in TEST_NAMES
                       if direct_dns_query(REFERENCE_SERVERS[0], name))
    facts["system_dns_ok"] = system_ok == len(TEST_NAMES)
    facts["reference_dns_ok"] = reference_ok == len(TEST_NAMES)
    if facts["system_dns_ok"]:
        stages.append(stage("DNS resolution", "pass",
                            "Your DNS answered " + str(system_ok) + " of " +
                            str(len(TEST_NAMES)) + " lookups."))
    elif system_ok > 0:
        stages.append(stage("DNS resolution", "warn",
                            "Your DNS answered only " + str(system_ok) + " of " +
                            str(len(TEST_NAMES)) + " lookups."))
    else:
        extra = " A known working server did answer." if facts["reference_dns_ok"] else ""
        stages.append(stage("DNS resolution", "fail",
                            "Your DNS answered 0 of " + str(len(TEST_NAMES)) + " lookups." + extra))

    # 6. Application connectivity
    if facts["system_dns_ok"]:
        started = time.time()
        web_ok = https_check(HTTPS_TEST_URL)
        facts["web_ms"] = round((time.time() - started) * 1000) if web_ok else None
        facts["https_ok"] = web_ok
        if web_ok:
            stages.append(stage("Application connectivity", "pass",
                                "Loaded " + HTTPS_TEST_URL + " over HTTPS."))
        else:
            stages.append(stage("Application connectivity", "fail",
                                "Could not load " + HTTPS_TEST_URL + " over HTTPS."))
    else:
        facts["https_ok"] = None
        facts["web_ms"] = None
        stages.append(stage("Application connectivity", "skip",
                            "Skipped because name lookups failed."))

    # 7. Router and WAN evidence
    stages.append(stage("Router and WAN evidence", "skip",
                        "No router login provided. Added in a later step."))

    return stages, facts


# ---------------------------------------------------------------
# Diagnosis. Follows the "How results are read" table on the page.
# ---------------------------------------------------------------

def diagnose(facts):
    if not facts["local_ip"]:
        return ("No network address",
                "This computer has no usable address, so it is probably not connected, "
                "or it did not get an address from the router.",
                "Check the cable or Wi-Fi connection, then check the router's address settings (DHCP).")

    if not facts["external_ok"]:
        if facts["gateway_received"] > 0:
            return ("Router reachable, internet not",
                    "The router answers, but nothing beyond it can be reached. "
                    "The cause is likely the router's internet side, or your provider.",
                    "Check the router's internet (WAN) status and restart the modem if you can.")
        return ("Cannot reach router or internet",
                "Nothing answered. The router may be off, or this computer may not be connected to it.",
                "Check that the router has power and that you are connected to it.")

    if not facts["system_dns_ok"]:
        if facts["reference_dns_ok"]:
            return ("DNS resolution failure",
                    "The internet works, but the DNS server this computer uses is not answering. "
                    "A known working server did answer, so this points to a DNS settings problem.",
                    "Check which DNS server is set, look for VPN or filtering software, then run again.")
        return ("DNS blocked or unavailable",
                "The internet works, but neither your DNS server nor the test DNS server answered. "
                "Something may be blocking DNS traffic.",
                "Check firewall, VPN, and router filtering settings, then run again.")

    if facts["https_ok"] is False:
        return ("Websites fail to load",
                "The connection and DNS work, but a web page would not load. "
                "This points to a proxy, VPN, certificate, or website problem.",
                "Check proxy and VPN settings and try another website.")

    if facts["gateway_sent"] and 0 < facts["gateway_received"] < facts["gateway_sent"]:
        return ("Some packet loss to the router",
                "Everything works, but some pings to the router were lost. "
                "This often means Wi-Fi interference or a weak signal.",
                "Compare a wired connection with Wi-Fi and run the test again.")

    if facts.get("gateway_avg") is not None and facts["gateway_avg"] > SLOW_ROUTER_MS:
        return ("Slow connection to the router",
                "Everything works, but your router is answering slowly (average " +
                str(facts["gateway_avg"]) + " ms). On a home network this usually points to "
                "Wi-Fi interference, a weak signal, or a busy router.",
                "Compare a wired connection with Wi-Fi, move closer to the router, and run the test again.")

    return ("No problem found",
            "All the tests that ran passed.",
            "If something still feels wrong, ask about a specific website or device.")


# ---------------------------------------------------------------
# Output
# ---------------------------------------------------------------

LABELS = {"pass": "[PASS]", "fail": "[FAIL]", "warn": "[WARN]", "skip": "[SKIP]"}


def build_report():
    """Run every check and return the full report as a dictionary."""
    stages, facts = run_checks()
    title, cause, next_step = diagnose(facts)
    return {
        "time": datetime.now().isoformat(timespec="seconds"),
        "computer": platform.node(),
        "stages": stages,
        "diagnosis": {"title": title, "likely_cause": cause, "next_step": next_step},
        "metrics": {
            "gateway": facts["gateway"],
            "local_ip": facts["local_ip"],
            "router_online": facts.get("gateway_received", 0) > 0,
            "internet_ok": facts["external_ok"],
            "router_ms": facts.get("gateway_avg"),
            "internet_ms": facts.get("internet_ms"),
            "dns_ms": facts.get("dns_ms"),
            "web_ms": facts.get("web_ms"),
        },
    }


def save_report(report):
    """Save the report next to this script."""
    folder = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(folder, "scrtncl-results.json"), "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)


def main():
    print("scrtncl Network Doctor (read-only)")
    print("Running checks. This takes up to about 30 seconds.\n")

    report = build_report()

    for number, item in enumerate(report["stages"], start=1):
        print(str(number) + ". " + LABELS[item["status"]] + " " + item["name"])
        print("      " + item["detail"])

    diagnosis = report["diagnosis"]
    print("\nDiagnosis: " + diagnosis["title"])
    print("Likely cause: " + diagnosis["likely_cause"])
    print("Next step: " + diagnosis["next_step"])
    print("Not verified: router logs, Wi-Fi signal, VPN or filter rules.")
    print("This is a likely cause, not a certain one.\n")

    save_report(report)
    print("Saved to scrtncl-results.json")


if __name__ == "__main__":
    main()
