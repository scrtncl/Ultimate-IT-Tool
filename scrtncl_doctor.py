"""
scrtncl engine, step 1: local Network Doctor.

Runs read-only checks on this computer's connection, prints a report,
and saves the same report to scrtncl-results.json.

Uses only the Python standard library. Nothing is changed on your
computer or router. The only traffic it sends is:
  - ping to your gateway (router)
  - connections to the public servers 1.1.1.1 and 8.8.8.8
  - DNS lookups and one HTTPS request to example.com

The page can also ask for a smaller check (local network only, or DNS
only) and can test a website you choose. Those checks are not saved to
your history, so they never change your ratings.

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

import scrtncl_quality
import scrtncl_wifi

OS = platform.system()  # "Windows", "Linux" or "Darwin" (macOS)

REFERENCE_SERVERS = ["1.1.1.1", "8.8.8.8"]
TEST_NAMES = ["example.com", "wikipedia.org"]
HTTPS_TEST_URL = "https://example.com"
# A result counts as slow (a warning) when scrtncl_quality would rate it poor.
POOR_INTERNET_DELAY_MS = lambda: scrtncl_quality.THRESHOLDS["internet_delay"][2]
POOR_DNS_MS = lambda: scrtncl_quality.THRESHOLDS["dns"][2]
POOR_WEB_MS = lambda: scrtncl_quality.THRESHOLDS["web"][2]
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


SCOPES = ("all", "local", "dns")
SCOPE_NAMES = {"all": "Full check", "local": "Local network only", "dns": "DNS only"}
BLOCKED_ENDINGS = ("local", "lan", "internal", "localhost", "home", "arpa", "test", "invalid", "example")
SITE_PATTERN = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def clean_site(text):
    """Check a website name typed on the page. Returns it cleaned, or raises ValueError."""
    site = (text or "").strip().lower()
    for prefix in ("https://", "http://"):
        if site.startswith(prefix):
            site = site[len(prefix):]
    site = site.rstrip("/")
    if not SITE_PATTERN.match(site) or site.rsplit(".", 1)[1] in BLOCKED_ENDINGS:
        raise ValueError("Please type a website name such as example.com (no paths, ports, or addresses).")
    return site


# ---------------------------------------------------------------
# The checks. Each returns a stage: name, status, detail.
# Status is one of: pass, fail, warn, skip
# ---------------------------------------------------------------

def stage(name, status, detail):
    return {"name": name, "status": status, "detail": detail}


def skipped(name, reason="Not part of this check."):
    return stage(name, "skip", reason)


def run_checks(scope="all", site=None):
    """Run the checks. scope is all, local, or dns. site is an optional website to test."""
    stages = []
    facts = {"wifi": None, "local_ip": None, "gateway": None, "external_ok": None,
             "site": site if scope in ("all", "dns") else None}
    do_local = scope in ("all", "local")
    do_internet = scope == "all"
    do_dns = scope in ("all", "dns")

    # 1. Physical and link (Wi-Fi details when this computer is on Wi-Fi)
    if do_local:
        wifi = scrtncl_wifi.get_wifi()
        facts["wifi"] = wifi
        if wifi["connected"]:
            where = wifi["band"] + ", " if wifi.get("band") else ""
            where += "channel " + str(wifi["channel"]) + ", " if wifi.get("channel") else ""
            speed = ", link speed " + str(round(wifi["rx_mbps"])) + " Mbps" if wifi.get("rx_mbps") else ""
            detail = ('Wi-Fi "' + str(wifi["ssid"]) + '", ' + where + "signal " +
                      str(wifi["signal_percent"]) + "% (about " + str(wifi["signal_dbm"]) +
                      " dBm)" + speed + ".")
            if wifi["quality"] == "weak":
                stages.append(stage("Physical and link", "warn", detail + " The signal is weak."))
            else:
                stages.append(stage("Physical and link", "pass", detail))
        else:
            stages.append(stage("Physical and link", "skip", wifi["reason"]))
    else:
        stages.append(skipped("Physical and link"))

    # 2. IP configuration
    if do_local:
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
    else:
        stages.append(skipped("IP configuration"))

    # 3. Local gateway
    if do_local:
        gateway = facts["gateway"]
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
    else:
        stages.append(skipped("Local gateway"))

    # 4. External connectivity (TCP is used because pings are often blocked)
    if do_internet:
        reachable = []
        connect_times = []
        for server in REFERENCE_SERVERS:
            milliseconds = tcp_connect(server, 53)
            if milliseconds is not None:
                connect_times.append(milliseconds)
                reachable.append(server + " (" + str(milliseconds) + " ms)")
        facts["external_ok"] = len(reachable) > 0
        facts["internet_ms"] = min(connect_times) if connect_times else None
        if reachable and facts["internet_ms"] > POOR_INTERNET_DELAY_MS():
            stages.append(stage("External connectivity", "warn",
                                "Reached " + ", ".join(reachable) + ", but the delay is high. "
                                "Calls, games, and page loads can feel sluggish."))
        elif reachable:
            stages.append(stage("External connectivity", "pass",
                                "Reached " + ", ".join(reachable) + "."))
        else:
            stages.append(stage("External connectivity", "fail",
                                "Could not reach any public test server."))
    else:
        stages.append(skipped("External connectivity"))

    # 5. DNS resolution
    if do_dns:
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
        if facts["system_dns_ok"] and facts["dns_ms"] is not None and facts["dns_ms"] > POOR_DNS_MS():
            dns_stage = stage("DNS resolution", "warn",
                              "Your DNS answered " + str(system_ok) + " of " + str(len(TEST_NAMES)) +
                              " lookups, but slowly (" + str(facts["dns_ms"]) + " ms on average).")
        elif facts["system_dns_ok"]:
            dns_stage = stage("DNS resolution", "pass",
                              "Your DNS answered " + str(system_ok) + " of " +
                              str(len(TEST_NAMES)) + " lookups.")
        elif system_ok > 0:
            dns_stage = stage("DNS resolution", "warn",
                              "Your DNS answered only " + str(system_ok) + " of " +
                              str(len(TEST_NAMES)) + " lookups.")
        else:
            extra = " A known working server did answer." if facts["reference_dns_ok"] else ""
            dns_stage = stage("DNS resolution", "fail",
                              "Your DNS answered 0 of " + str(len(TEST_NAMES)) + " lookups." + extra)
        if site:
            facts["site_dns_ok"] = system_dns_lookup(site)
            if facts["site_dns_ok"]:
                dns_stage["detail"] += " The lookup for " + site + " worked."
            else:
                dns_stage["detail"] += " The lookup for " + site + " failed."
                if dns_stage["status"] == "pass":
                    dns_stage["status"] = "warn"
        stages.append(dns_stage)
    else:
        stages.append(skipped("DNS resolution"))

    # 6. Application connectivity
    if do_internet:
        url = "https://" + site if site else HTTPS_TEST_URL
        if facts["system_dns_ok"] and (not site or facts.get("site_dns_ok")):
            started = time.time()
            web_ok = https_check(url)
            facts["web_ms"] = round((time.time() - started) * 1000) if web_ok else None
            facts["https_ok"] = web_ok
            if site and not web_ok:
                # Does an ordinary website load? This tells "one site fails" from "none load".
                facts["baseline_https_ok"] = https_check(HTTPS_TEST_URL)
            if web_ok and facts["web_ms"] > POOR_WEB_MS():
                stages.append(stage("Application connectivity", "warn",
                                    "Loaded " + url + " over HTTPS, but slowly (" +
                                    str(facts["web_ms"]) + " ms)."))
            elif web_ok:
                stages.append(stage("Application connectivity", "pass",
                                    "Loaded " + url + " over HTTPS."))
            else:
                stages.append(stage("Application connectivity", "fail",
                                    "Could not load " + url + " over HTTPS."))
        else:
            facts["https_ok"] = None
            facts["web_ms"] = None
            why = ("Skipped because the lookup for " + site + " failed."
                   if facts["system_dns_ok"] else "Skipped because name lookups failed.")
            stages.append(stage("Application connectivity", "skip", why))
    else:
        stages.append(skipped("Application connectivity"))

    # 7. Router and WAN evidence
    stages.append(stage("Router and WAN evidence", "skip",
                        "No router login provided. Added in a later step." if scope == "all"
                        else "Not part of this check."))

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

    site = facts.get("site")
    if site and facts.get("site_dns_ok") is False:
        return ("Only this website's name fails",
                "The default test names resolved, but " + site + " did not. "
                "The name may be misspelled, or that website's DNS may be down.",
                "Check the spelling, try again later, or try another DNS server to compare.")

    if site and facts["https_ok"] is False and facts.get("baseline_https_ok"):
        return ("Only this website fails to load",
                "An ordinary website loads, but " + site + " did not. "
                "This points to that website, or to something blocking it.",
                "Try again later and check VPN, filtering, or parental-control settings.")

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

    wifi = facts.get("wifi") or {}
    if wifi.get("connected") and wifi.get("quality") == "weak":
        return ("Weak Wi-Fi signal",
                "Everything works, but your Wi-Fi signal is weak (" + str(wifi["signal_percent"]) +
                "%). A weak signal often causes slow speeds and dropped connections.",
                "Move closer to the router or extender, or try a wired connection, and run the test again.")

    if facts.get("gateway_avg") is not None and facts["gateway_avg"] > SLOW_ROUTER_MS:
        return ("Slow connection to the router",
                "Everything works, but your router is answering slowly (average " +
                str(facts["gateway_avg"]) + " ms). On a home network this usually points to "
                "Wi-Fi interference, a weak signal, or a busy router.",
                "Compare a wired connection with Wi-Fi, move closer to the router, and run the test again.")

    if facts.get("dns_ms") is not None and facts["dns_ms"] > POOR_DNS_MS():
        return ("Slow DNS lookups",
                "Everything works, but name lookups are slow (" + str(facts["dns_ms"]) + " ms on average). "
                "Pages will be slow to start loading.",
                "Run the test again to see if it keeps happening. If it does, try a different DNS server "
                "to compare. On a phone hotspot, a weak mobile signal can cause this.")

    if facts.get("internet_ms") is not None and facts["internet_ms"] > POOR_INTERNET_DELAY_MS():
        return ("High delay to the internet",
                "Everything works, but the delay to the internet is high (" + str(facts["internet_ms"]) +
                " ms). If your router answers quickly, the delay is probably at your provider or, "
                "on a phone hotspot, in the mobile signal.",
                "Run the test again, and compare it with another connection if you can.")

    if facts.get("web_ms") is not None and facts["web_ms"] > POOR_WEB_MS():
        return ("Slow web page loading",
                "Everything works, but loading a web page took " + str(facts["web_ms"]) + " ms.",
                "Run the test again and try another website.")

    return ("No problem found",
            "All the tests that ran passed.",
            "If something still feels wrong, ask about a specific website or device.")


def diagnose_local(facts):
    """Diagnosis for the 'Local network only' check."""
    if not facts.get("local_ip"):
        return ("No network address",
                "This computer has no usable address, so it is probably not connected, "
                "or it did not get an address from the router.",
                "Check the cable or Wi-Fi connection, then check the router's address settings (DHCP).")
    if not facts.get("gateway"):
        return ("No router found",
                "This computer has an address but could not find a router to send traffic to.",
                "Check the router and your connection to it, then run the check again.")
    received = facts.get("gateway_received", 0)
    sent = facts.get("gateway_sent", 0)
    if received == 0:
        return ("Router did not answer",
                "The router did not answer pings. Some routers block pings on purpose, so this does not "
                "prove it is down. Only the local network was checked.",
                "Run the full check to see whether the internet still works.")
    if sent and received < sent:
        return ("Some packet loss to the router",
                "Some pings to the router were lost. This often means Wi-Fi interference or a weak signal.",
                "Compare a wired connection with Wi-Fi and run the check again.")
    wifi = facts.get("wifi") or {}
    if wifi.get("connected") and wifi.get("quality") == "weak":
        return ("Weak Wi-Fi signal",
                "Your Wi-Fi signal is weak (" + str(wifi["signal_percent"]) + "%). "
                "A weak signal often causes slow speeds and dropped connections.",
                "Move closer to the router or extender, or try a wired connection, and run the check again.")
    if facts.get("gateway_avg") is not None and facts["gateway_avg"] > SLOW_ROUTER_MS:
        return ("Slow connection to the router",
                "Your router is answering slowly (average " + str(facts["gateway_avg"]) + " ms). "
                "On a home network this usually points to Wi-Fi interference, a weak signal, or a busy router.",
                "Compare a wired connection with Wi-Fi, move closer to the router, and run the check again.")
    return ("Local network looks fine",
            "Your connection to the router works. Only the local network was checked, "
            "so the internet and DNS were not tested.",
            "Run the full check if something still feels wrong.")


def diagnose_dns(facts):
    """Diagnosis for the 'DNS only' check."""
    if not facts.get("system_dns_ok"):
        if facts.get("reference_dns_ok"):
            return ("DNS resolution failure",
                    "The DNS server this computer uses did not answer, but a known working server did. "
                    "This points to a DNS settings problem.",
                    "Check which DNS server is set, look for VPN or filtering software, then run again.")
        return ("DNS did not answer",
                "Neither your DNS server nor the test DNS server answered. Something may be blocking DNS, "
                "or there may be no internet connection. Only DNS was checked.",
                "Run the full check to tell these apart.")
    site = facts.get("site")
    if site and facts.get("site_dns_ok") is False:
        return ("Only this website's name fails",
                "The default test names resolved, but " + site + " did not. "
                "The name may be misspelled, or that website's DNS may be down.",
                "Check the spelling, try again later, or try another DNS server to compare.")
    if facts.get("dns_ms") is not None and facts["dns_ms"] > POOR_DNS_MS():
        return ("Slow DNS lookups",
                "Name lookups work but are slow (" + str(facts["dns_ms"]) + " ms on average). "
                "Pages will be slow to start loading.",
                "Run the check again. If it keeps happening, try a different DNS server to compare.")
    return ("DNS works",
            "Your DNS answered every lookup. Only DNS was checked.",
            "Run the full check if something still feels wrong.")


# ---------------------------------------------------------------
# Output
# ---------------------------------------------------------------

LABELS = {"pass": "[PASS]", "fail": "[FAIL]", "warn": "[WARN]", "skip": "[SKIP]"}


def build_report(scope="all", site=None):
    """Run the checks and return the full report as a dictionary."""
    if scope not in SCOPES:
        scope = "all"
    stages, facts = run_checks(scope, site)
    if scope == "local":
        title, cause, next_step = diagnose_local(facts)
    elif scope == "dns":
        title, cause, next_step = diagnose_dns(facts)
    else:
        title, cause, next_step = diagnose(facts)
    return {
        "time": datetime.now().isoformat(timespec="seconds"),
        "computer": platform.node(),
        "scope": scope,
        "site": facts.get("site"),
        "stages": stages,
        "diagnosis": {"title": title, "likely_cause": cause, "next_step": next_step},
        "metrics": {
            "gateway": facts.get("gateway"),
            "local_ip": facts.get("local_ip"),
            "router_online": facts.get("gateway_received", 0) > 0,
            "internet_ok": facts.get("external_ok"),
            "router_ms": facts.get("gateway_avg"),
            "internet_ms": facts.get("internet_ms"),
            "dns_ms": facts.get("dns_ms"),
            "web_ms": facts.get("web_ms"),
            "wifi": facts.get("wifi"),
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
