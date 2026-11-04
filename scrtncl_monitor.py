"""
scrtncl engine, step 6: background monitoring.

While the server is running, this takes a quick, read-only health sample
every few minutes, even if no page is open:
  - is your router answering, and how fast
  - can the internet be reached, and how fast
  - how long a DNS lookup takes
  - your Wi-Fi signal
Samples are saved in scrtncl-history.jsonl (14 days are kept). Changes
between samples become events in scrtncl-events.json, for example
"Connection lost" and "Connection restored after about 4 min".

A sample is light: a couple of pings to your router, two small
connections to public servers, and one DNS lookup. It is not a speed
test and never changes anything.

Monitoring only runs while the server is running. If the computer sleeps
or the server is stopped, the history shows a gap and an event says so.
"""

import json
import os
import random
import socket
import threading
import time
from datetime import datetime, timedelta

import scrtncl_doctor as doctor
import scrtncl_settings
import scrtncl_wifi

FOLDER = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(FOLDER, "scrtncl-history.jsonl")
EVENTS_FILE = os.path.join(FOLDER, "scrtncl-events.json")

INTERVAL_MINUTES = 5
KEEP_DAYS = 14
MAX_EVENTS = 300

running = False   # set when the background loop has been started


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def parse_time(iso):
    return datetime.fromisoformat(iso)


# ---------------------------------------------------------------
# Taking a sample
# ---------------------------------------------------------------

def dns_delay_ms(timeout=3):
    """Time a DNS lookup for a name that cannot be cached.

    The name does not exist, so the answer is 'not found'. What matters is
    how long your DNS server took to answer.
    """
    name = "scrtncl-" + str(random.randint(0, 10**9)) + ".example.com"
    result = {}

    def work():
        started = time.time()
        try:
            socket.getaddrinfo(name, 443)
        except socket.gaierror as error:
            result["error"] = error
        except Exception:
            result["other"] = True
        result["ms"] = (time.time() - started) * 1000

    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    worker.join(timeout)
    if "ms" not in result or "other" in result:
        return None
    error = result.get("error")
    if error is not None and error.errno != socket.EAI_NONAME:
        return None  # the DNS server did not really answer
    return round(result["ms"])


def take_sample():
    local_ip = doctor.get_local_ip()
    gateway = doctor.get_gateway() if local_ip else None
    wifi = scrtncl_wifi.get_wifi()

    router_online = False
    router_ms = None
    if gateway:
        received, sent, average = doctor.ping(gateway, count=2)
        router_online = received > 0
        router_ms = average

    connect_times = []
    for server in doctor.REFERENCE_SERVERS:
        milliseconds = doctor.tcp_connect(server, 53, timeout=2)
        if milliseconds is not None:
            connect_times.append(milliseconds)
    internet_ok = len(connect_times) > 0

    return {
        "t": now_iso(),
        "local_ip": local_ip,
        "gateway": gateway,
        "router_online": router_online,
        "router_ms": router_ms,
        "internet_ok": internet_ok,
        "internet_ms": min(connect_times) if connect_times else None,
        "dns_ms": dns_delay_ms() if internet_ok else None,
        "wifi_connected": bool(wifi.get("connected")),
        "wifi_signal": wifi.get("signal_percent") if wifi.get("connected") else None,
    }


# ---------------------------------------------------------------
# History file
# ---------------------------------------------------------------

def append_history(sample, history_file=HISTORY_FILE):
    with open(history_file, "a", encoding="utf-8") as file:
        file.write(json.dumps(sample) + "\n")


def read_all_history(history_file=HISTORY_FILE):
    samples = []
    try:
        with open(history_file, encoding="utf-8") as file:
            for line in file:
                try:
                    samples.append(json.loads(line))
                except ValueError:
                    continue  # skip a damaged line
    except OSError:
        pass
    return samples


def prune_history(history_file=HISTORY_FILE, keep_days=KEEP_DAYS):
    cutoff = (datetime.now() - timedelta(days=keep_days)).isoformat(timespec="seconds")
    samples = read_all_history(history_file)
    kept = [sample for sample in samples if sample.get("t", "") >= cutoff]
    if len(kept) != len(samples):
        with open(history_file, "w", encoding="utf-8") as file:
            for sample in kept:
                file.write(json.dumps(sample) + "\n")


# ---------------------------------------------------------------
# Events
# ---------------------------------------------------------------

def load_events(events_file=EVENTS_FILE):
    try:
        with open(events_file, encoding="utf-8") as file:
            data = json.load(file)
        if isinstance(data.get("events"), list):
            data.setdefault("state", {})
            return data
    except (OSError, ValueError):
        pass
    return {"state": {}, "events": []}


def save_events(data, events_file=EVENTS_FILE):
    data["events"] = data["events"][:MAX_EVENTS]
    with open(events_file, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def connection_state(sample):
    if sample["internet_ok"]:
        return "online"
    return "no_internet" if sample["router_online"] else "offline"


def describe_duration(seconds):
    minutes = round(seconds / 60)
    if minutes < 1:
        return "less than a minute"
    if minutes < 120:
        return "about " + str(minutes) + " min"
    return "about " + str(round(minutes / 60, 1)) + " hours"


def add_event(level, message, detail="", when=None, events_file=EVENTS_FILE):
    data = load_events(events_file)
    data["events"].insert(0, {"time": when or now_iso(), "level": level,
                              "message": message, "detail": detail})
    save_events(data, events_file)


def process_sample(sample, interval_minutes=None, history_file=HISTORY_FILE,
                   events_file=EVENTS_FILE, settings=None):
    """Save a sample and turn any change since the last one into events."""
    settings = settings or scrtncl_settings.load_settings()
    if interval_minutes is None:
        interval_minutes = settings["monitor_minutes"]
    data = load_events(events_file)
    state = data["state"]
    events = data["events"]
    now = parse_time(sample["t"])

    def add(level, message, detail="", kind=None):
        # The alert settings decide which kinds of event are written down.
        if kind == "connection" and not settings["alert_connection"]:
            return
        if kind == "wifi" and not settings["alert_wifi"]:
            return
        events.insert(0, {"time": sample["t"], "level": level, "message": message, "detail": detail})

    last = state.get("last_sample")
    if last:
        gap = (now - parse_time(last)).total_seconds()
        if gap > interval_minutes * 60 * 3:
            add("info", "No monitoring for " + describe_duration(gap),
                "The computer may have been asleep, or scrtncl was not running. "
                "Anything that happened in that time was not recorded.")

    new_state = connection_state(sample)
    old_state = state.get("name")
    if old_state and old_state != new_state:
        since = state.get("since")
        if new_state == "online":
            lasted = describe_duration((now - parse_time(since)).total_seconds()) if since else "an unknown time"
            add("up", "Connection restored", "The internet was unreachable for " + lasted + ".", "connection")
        elif old_state == "online" and new_state == "no_internet":
            add("down", "Internet connection lost", "Your router still answers, so the problem is beyond it.", "connection")
        elif old_state == "online":
            add("down", "Connection lost", "Neither your router nor the internet answered.", "connection")
        elif new_state == "offline":
            add("warn", "Router stopped answering", "The internet is still unreachable.", "connection")
        else:
            add("warn", "Router answering again", "The internet is still unreachable.", "connection")
        state["since"] = sample["t"]
    elif not old_state:
        state["since"] = sample["t"]
    state["name"] = new_state

    previous_wifi = state.get("wifi_connected")
    if previous_wifi is True and not sample["wifi_connected"]:
        add("warn", "Wi-Fi disconnected", "", "wifi")
    elif previous_wifi is False and sample["wifi_connected"]:
        add("info", "Wi-Fi connected", "", "wifi")
    state["wifi_connected"] = sample["wifi_connected"]

    previous_gateway = state.get("gateway")
    if previous_gateway and sample["gateway"] and previous_gateway != sample["gateway"]:
        add("info", "Network changed",
            "Your gateway changed from " + previous_gateway + " to " + sample["gateway"] +
            ", so you are on a different router or network.")
    if sample["gateway"]:
        state["gateway"] = sample["gateway"]

    state["last_sample"] = sample["t"]
    save_events(data, events_file)
    append_history(sample, history_file)


# ---------------------------------------------------------------
# What the pages ask for
# ---------------------------------------------------------------

def get_history(hours, history_file=HISTORY_FILE, events_file=EVENTS_FILE):
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat(timespec="seconds")
    samples = [s for s in read_all_history(history_file) if s.get("t", "") >= cutoff]
    data = load_events(events_file)
    events = [e for e in data["events"] if e.get("time", "") >= cutoff][:100]
    return {
        "interval_minutes": scrtncl_settings.load_settings()["monitor_minutes"],
        "hours": hours,
        "now": now_iso(),
        "last_sample": data["state"].get("last_sample"),
        "samples": samples,
        "events": events,
    }


# ---------------------------------------------------------------
# The background loop
# ---------------------------------------------------------------

def status():
    """What the Settings page shows about monitoring."""
    settings = scrtncl_settings.load_settings()
    return {
        "running": running,
        "enabled": settings["monitor_enabled"],
        "interval_minutes": settings["monitor_minutes"],
        "last_sample": load_events()["state"].get("last_sample"),
    }


def loop(lock):
    time.sleep(3)
    last_prune = time.time()
    next_due = 0.0
    while True:
        try:
            settings = scrtncl_settings.load_settings()
            if settings["monitor_enabled"] and time.time() >= next_due:
                if lock.acquire(timeout=120):
                    try:
                        sample = take_sample()
                    finally:
                        lock.release()
                    process_sample(sample, settings=settings)
                next_due = time.time() + settings["monitor_minutes"] * 60
            if time.time() - last_prune > 86400:
                prune_history()
                last_prune = time.time()
        except Exception as error:
            print("Monitoring skipped one sample: " + str(error))
        time.sleep(15)


def start(lock):
    """Start monitoring in the background. Call once when the server starts."""
    global running
    prune_history()
    minutes = scrtncl_settings.load_settings()["monitor_minutes"]
    add_event("info", "Monitoring started", "Checking every " + str(minutes) + " minutes.")
    running = True
    threading.Thread(target=loop, args=(lock,), daemon=True).start()


if __name__ == "__main__":
    print("Taking one sample (nothing is saved):")
    print(take_sample())
