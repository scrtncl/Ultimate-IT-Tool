"""
scrtncl engine: the technician.

Answers questions about your network. It is a set of rules reading your
own saved data, not an AI model:
  - the last Network Doctor check          (scrtncl-results.json)
  - the last speed test                    (scrtncl-speed.json)
  - the monitoring history and events      (scrtncl-history.jsonl, scrtncl-events.json)
  - the last device scan                   (scrtncl-devices.json)
  - your settings, such as your plan speed (scrtncl-settings.json)

Nothing leaves this computer, nothing is tested while you ask, and
nothing on your network is ever changed. Each answer keeps apart:
  - what was measured
  - the most likely cause, with the evidence and a confidence level
  - what could not be verified
  - tests to run next
  - fixes you could try (suggestions only, never applied)

Confidence comes from how many separate measurements support a cause:
one is low, two is medium, three or more is high. It is not a guess about
how sure the wording sounds.

Try it on its own with:   python scrtncl_technician.py "why is my internet slow?"
"""

import re
import statistics
import sys
from datetime import datetime

import scrtncl_monitor
import scrtncl_quality
import scrtncl_scan
import scrtncl_settings

try:
    import scrtncl_speed
except ImportError:          # the technician still works without a speed test
    scrtncl_speed = None

SAFETY = "The technician explains and suggests. It never changes anything on your network."
HISTORY_HOURS = 168          # a week of monitoring history
STALE_HOURS = 24             # a saved check older than this may not match now
EVENING_HOURS = range(18, 24)
HOTSPOT_PREFIXES = ("172.20.10.", "192.168.43.", "10.141.", "10.42.")

INTENT_WORDS = {
    "devices": ["who is on", "who's on", "device", "devices", "intruder", "stranger", "someone", "unknown",
                "stealing", "connected to my network", "on my network"],
    "wifi": ["wifi", "wireless", "signal", "extender", "range"],
    "dns": ["dns", "website", "websites", "webpage", "web page", "page load", "won't load", "wont load",
            "can't open", "cant open", "not loading"],
    "drops": ["drop", "drops", "dropping", "disconnect", "disconnects", "unstable", "cuts out", "cut out",
              "intermittent", "outage", "outages", "keeps", "reconnect", "lost connection", "going down"],
    "slow": ["slow", "speed", "speeds", "lag", "laggy", "buffer", "buffering", "evening", "night", "ping",
             "latency", "delay", "performance", "mbps", "download", "upload", "fast"],
    "status": ["working", "online", "status", "right now", "internet up", "is it up", "healthy", "ok", "okay"],
}
INTENT_ORDER = ["devices", "wifi", "dns", "drops", "slow", "status"]
UNDERSTOOD = {
    "devices": "I took this as a question about the devices on your network.",
    "wifi": "I took this as a question about your Wi-Fi.",
    "dns": "I took this as a question about DNS and websites not loading.",
    "drops": "I took this as a question about the connection dropping.",
    "slow": "I took this as a question about slowness.",
    "status": "I took this as a question about whether your internet works right now.",
}


# ---------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------

def parse_time(iso):
    try:
        return datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return None


def hours_since(iso):
    moment = parse_time(iso)
    if moment is None:
        return None
    return max(0.0, (datetime.now() - moment).total_seconds() / 3600)


def ago(iso):
    hours = hours_since(iso)
    if hours is None:
        return "at an unknown time"
    minutes = round(hours * 60)
    if minutes < 2:
        return "just now"
    if minutes < 120:
        return str(minutes) + " min ago"
    if hours < 48:
        return str(round(hours)) + " h ago"
    return str(round(hours / 24)) + " days ago"


def values_of(samples, key):
    return [s[key] for s in samples if isinstance(s.get(key), (int, float)) and not isinstance(s.get(key), bool)]


def median(values):
    return statistics.median(values) if values else None


def percent(part, whole):
    return round(100 * part / whole) if whole else 0


def plural(count, word):
    return str(count) + " " + word + ("" if count == 1 else "s")


def safe_call(function, default=None):
    try:
        return function()
    except Exception:
        return default


# ---------------------------------------------------------------
# Gathering the saved data
# ---------------------------------------------------------------

def gather():
    settings = scrtncl_settings.load_settings()
    results = safe_call(scrtncl_quality.load_results)
    speed = safe_call(lambda: scrtncl_speed.load_last_result()) if scrtncl_speed else None
    if speed is not None and not speed.get("ok"):
        speed = None
    history = safe_call(lambda: scrtncl_monitor.get_history(HISTORY_HOURS),
                        {"samples": [], "events": [], "interval_minutes": settings["monitor_minutes"]})
    devices = safe_call(scrtncl_scan.load_last_report)
    quality = safe_call(lambda: scrtncl_quality.assess(results, speed, settings))
    metrics = (results or {}).get("metrics") or {}
    items = {item["key"]: item for item in (quality or {}).get("items", [])}
    return {
        "settings": settings, "results": results, "metrics": metrics, "speed": speed,
        "history": history, "samples": history.get("samples", []), "events": history.get("events", []),
        "devices": devices, "quality": quality, "items": items,
    }


def rating(data, key):
    item = data["items"].get(key)
    return item["rating"] if item else None


def item_text(data, key):
    item = data["items"].get(key)
    return item["value"] if item and item["rating"] else None


def source_lines(data, used):
    lines = []
    if "results" in used and data["results"]:
        lines.append("Latest Network Doctor check (" + ago(data["results"].get("time")) + ")")
    if "speed" in used and data["speed"]:
        lines.append("Latest speed test (" + ago(data["speed"].get("time")) + ")")
    if "history" in used and data["samples"]:
        lines.append("Monitoring history (" + plural(len(data["samples"]), "sample") + " over " + coverage(data["samples"]) + ")")
    if "devices" in used and data["devices"]:
        lines.append("Latest device scan (" + ago(data["devices"].get("time")) + ")")
    if "settings" in used and (data["settings"].get("plan_download_mbps") or data["settings"].get("plan_upload_mbps")):
        lines.append("Your plan speed from Settings")
    return lines


def coverage(samples):
    if not samples:
        return "no time"
    first, last = parse_time(samples[0].get("t")), parse_time(samples[-1].get("t"))
    if first is None or last is None:
        return "an unknown period"
    hours = (last - first).total_seconds() / 3600
    if hours < 1:
        return "less than an hour"
    if hours < 48:
        return str(round(hours)) + " hours"
    return str(round(hours / 24, 1)) + " days"


# ---------------------------------------------------------------
# Causes
# ---------------------------------------------------------------

class Causes:
    """Collects likely causes. Confidence is decided by how much evidence there is."""

    def __init__(self):
        self.entries = []

    def add(self, key, cause, evidence):
        if evidence:
            level = "low" if len(evidence) == 1 else "medium" if len(evidence) == 2 else "high"
            self.entries.append({"key": key, "cause": cause, "confidence": level, "evidence": evidence})

    def ranked(self):
        order = {"high": 0, "medium": 1, "low": 2}
        return sorted(self.entries, key=lambda e: (order[e["confidence"]], -len(e["evidence"])))

    def output(self):
        return [{"cause": e["cause"], "confidence": e["confidence"], "evidence": e["evidence"]}
                for e in self.ranked()]


TESTS = {
    "wifi": "Run the Network Doctor once close to the router (or on a cable) and compare the signal and delay.",
    "router": "Run the Network Doctor on a cable instead of Wi-Fi and compare the router delay.",
    "provider": "Run a speed test and the Network Doctor again at a different time of day and compare.",
    "busy": "Run the speed test while nothing else on the network is downloading or streaming, and compare the extra delay.",
    "dns": "Run the Network Doctor's DNS only check, then try again after switching the DNS server to compare.",
    "hotspot": "Move the phone to where the mobile signal is stronger and run the speed test again.",
    "evening": "Run the speed test at the time it feels slow, and again in the morning, and compare.",
    "internet_drop": "Leave the server running so monitoring records the next drop, then check the Overview's history.",
    "local_drop": "Run the Network Doctor on a cable while it is dropping, to see whether the router itself stops answering.",
    "wifi_drop": "Watch the Wi-Fi signal in the History panel around the time of the next drop.",
}
FIXES = {
    "wifi": ["Move closer to the router or extender, or use a network cable.",
             "If you use an extender, place it where it still gets a strong signal from the main router.",
             "Try the 5 GHz band for speed, or the 2.4 GHz band for range, in your router's Wi-Fi settings."],
    "router": ["Restart the router by unplugging it for about 30 seconds.",
               "Check whether another device is using a lot of the connection while you test.",
               "Try a cable to rule out Wi-Fi interference."],
    "provider": ["Restart the modem or router once and test again.",
                 "Keep a note of the times and the measured delay and speed, and show it to your provider if it keeps happening."],
    "busy": ["If your router has Smart Queue Management or QoS, turn it on.",
             "Pause large downloads or uploads while you need calls or games to be smooth."],
    "dns": ["Try a different DNS server, such as 1.1.1.1 or 8.8.8.8, on this computer or the router, then check again.",
            "On Windows, clearing the DNS cache with ipconfig /flushdns can help after a DNS change.",
            "Turn off a VPN or filtering software briefly to see whether it is the cause."],
    "hotspot": ["Move the phone to a spot with better mobile signal.",
                "Check whether your mobile plan slows data after a limit.",
                "Restarting the phone's hotspot (turn off and on again) can clear a stale connection.",
                "Try placing the phone near a window or higher up where cellular reception is often stronger."],
    "evening": ["Compare the speed in the morning and in the evening, and keep the numbers.",
                "If evenings are always much slower, ask your provider about congestion in your area."],
    "internet_drop": ["Restart the modem or router once.",
                      "Show your provider the times of the drops from the History panel if they keep happening."],
    "local_drop": ["Check the router's power and cables, and restart it.",
                   "If the router is hot or very old, it may be failing."],
    "wifi_drop": ["Move closer to the router or extender, or use a cable.",
                  "Check for the router and extender being on very different channels or far apart."],
}


def tests_and_fixes(causes, general_tests):
    tests, fixes = [], []
    for entry in causes.ranked()[:2]:
        text = TESTS.get(entry["key"])
        if text and text not in tests:
            tests.append(text)
        for fix in FIXES.get(entry["key"], []):
            if fix not in fixes and len(fixes) < 5:
                fixes.append(fix)
    for text in general_tests:
        if text not in tests:
            tests.append(text)
    return tests, fixes


# ---------------------------------------------------------------
# Shared facts
# ---------------------------------------------------------------

def freshness_unknowns(data):
    unknown = []
    results = data["results"]
    if results is None:
        unknown.append("No Network Doctor check has been saved yet, so there are no stage-by-stage results.")
    else:
        hours = hours_since(results.get("time"))
        if hours is not None and hours > STALE_HOURS:
            unknown.append("The last Network Doctor check is " + ago(results.get("time")) + ", so it may not match how things are now.")
    return unknown


def no_data(data):
    return not data["results"] and not data["speed"] and not data["samples"]


def empty_answer(title, understood):
    return {
        "title": title, "understood_as": understood,
        "paragraphs": ["There is no saved data yet, so I have nothing to base an answer on. "
                       "Run the Network Doctor on its page, then ask again."],
        "measured": [], "causes": [], "unknown": ["Everything: no checks, speed tests, or monitoring samples are saved."],
        "tests": ["Run the Network Doctor.", "Run a speed test from the Overview."],
        "fixes": [], "sources": [], "safety": SAFETY,
    }


def measured_lines(data, keys):
    lines = []
    for key in keys:
        item = data["items"].get(key)
        if item and item["rating"]:
            lines.append(item["label"] + ": " + item["value"] + " (rated " + item["rating"] + ")")
    return lines


def history_delay_share(data, key, limit):
    values = values_of(data["samples"], key)
    if len(values) < 6:
        return None
    return percent(sum(1 for v in values if v > limit), len(values)), len(values)


def evening_comparison(data):
    evening, other = [], []
    for sample in data["samples"]:
        value = sample.get("internet_ms")
        moment = parse_time(sample.get("t"))
        if moment is None or not isinstance(value, (int, float)):
            continue
        (evening if moment.hour in EVENING_HOURS else other).append(value)
    if len(evening) < 6 or len(other) < 6:
        return None
    return median(evening), median(other), len(evening), len(other)


def is_hotspot(data):
    gateway = data["metrics"].get("gateway") or ""
    return gateway if gateway.startswith(HOTSPOT_PREFIXES) else None


# ---------------------------------------------------------------
# Answers
# ---------------------------------------------------------------

def answer_slow(data):
    understood = UNDERSTOOD["slow"]
    if no_data(data):
        return empty_answer("Why is it slow", understood)

    causes = Causes()
    wifi_weak = rating(data, "wifi") in ("fair", "poor")
    low_speed = rating(data, "download") in ("fair", "poor")
    router_ok = rating(data, "router_delay") in ("excellent", "good")
    router_slow = rating(data, "router_delay") in ("fair", "poor")
    delay_high = rating(data, "internet_delay") in ("fair", "poor")

    wifi_history = values_of(data["samples"], "wifi_signal")
    if wifi_weak:
        evidence = ["Wi-Fi signal: " + item_text(data, "wifi") + ", rated " + rating(data, "wifi") + "."]
        if router_slow:
            evidence.append("Router replies are slow: " + item_text(data, "router_delay") + ".")
        if low_speed:
            evidence.append("Download speed is low: " + item_text(data, "download") + ".")
        if len(wifi_history) >= 6 and statistics.mean(wifi_history) < 70:
            evidence.append("The average signal in the monitoring history is " + str(round(statistics.mean(wifi_history))) + "%.")
        causes.add("wifi", "A weak Wi-Fi signal between this computer and the router or extender", evidence)

    if router_slow and not wifi_weak:
        evidence = ["Router replies are slow: " + item_text(data, "router_delay") + "."]
        if low_speed:
            evidence.append("Download speed is low: " + item_text(data, "download") + ".")
        share = history_delay_share(data, "router_ms", 20)
        if share and share[0] >= 30:
            evidence.append(str(share[0]) + "% of the " + str(share[1]) + " monitoring samples had a router delay above 20 ms.")
        causes.add("router", "Your own network is slow to respond (router busy, or Wi-Fi interference)", evidence)

    gateway = is_hotspot(data)
    if gateway and (low_speed or delay_high or wifi_weak):
        evidence = ["Your gateway address (" + gateway + ") is the one phones use for a hotspot."]
        if low_speed:
            evidence.append("Download speed is low: " + item_text(data, "download") + ".")
        if delay_high:
            evidence.append("The delay to the internet is high: " + item_text(data, "internet_delay") + ".")
        if not wifi_weak and item_text(data, "wifi"):
            evidence.append("Wi-Fi to the phone is strong (" + item_text(data, "wifi") + "), so the bottleneck is the mobile signal.")
        causes.add("hotspot", "You are on a phone hotspot, where speed depends on the mobile signal", evidence)

    if not gateway and router_ok and not wifi_weak and (delay_high or low_speed):
        evidence = ["Your router answers quickly: " + item_text(data, "router_delay") + "."]
        if delay_high:
            evidence.append("The delay to the internet is high: " + item_text(data, "internet_delay") + ".")
        if low_speed:
            evidence.append("Download speed is low: " + item_text(data, "download") + ".")
        share = history_delay_share(data, "internet_ms", 120)
        if share and share[0] >= 30:
            evidence.append(str(share[0]) + "% of the " + str(share[1]) + " monitoring samples had an internet delay above 120 ms.")
        causes.add("provider", "The slowness is probably beyond your own network, at your provider", evidence)

    if rating(data, "busy_delay") in ("fair", "poor"):
        evidence = ["The delay rises when the connection is busy: " + item_text(data, "busy_delay") + "."]
        if low_speed:
            evidence.append("Download speed is low: " + item_text(data, "download") + ".")
        causes.add("busy", "The connection gets congested when it is busy (queueing in the router or modem)", evidence)

    if rating(data, "dns") in ("fair", "poor"):
        evidence = ["DNS lookups are slow: " + item_text(data, "dns") + "."]
        if rating(data, "web") in ("fair", "poor"):
            evidence.append("Web pages are slow to load: " + item_text(data, "web") + ".")
        share = history_delay_share(data, "dns_ms", 150)
        if share and share[0] >= 30:
            evidence.append(str(share[0]) + "% of the " + str(share[1]) + " monitoring samples had a DNS time above 150 ms.")
        causes.add("dns", "Slow DNS lookups make pages slow to start loading", evidence)

    comparison = evening_comparison(data)
    if comparison and comparison[0] >= 1.5 * comparison[1] and comparison[0] - comparison[1] >= 15:
        evidence = ["The typical delay to the internet is " + str(round(comparison[0])) + " ms in the evening (6 pm to midnight) "
                    "and " + str(round(comparison[1])) + " ms at other times."]
        if min(comparison[2], comparison[3]) >= 30:
            evidence.append("This is based on " + str(comparison[2]) + " evening and " + str(comparison[3]) + " other samples.")
        causes.add("evening", "The connection is slower in the evening, which is typical of a busy shared network", evidence)

    measured = measured_lines(data, ["download", "upload", "internet_delay", "busy_delay", "router_delay", "dns", "web", "wifi"])
    paragraphs = []
    if data["quality"] and data["quality"].get("label") == "Offline":
        paragraphs.append("The latest check found no internet connection, so this is an outage rather than slowness. " +
                          data["quality"]["summary"])
    elif causes.entries:
        paragraphs.append("Your measurements show something that could explain slowness. " + (data["quality"] or {}).get("summary", ""))
    else:
        paragraphs.append("Your saved measurements look healthy, so I cannot point to a cause from the data. "
                          "Slowness that comes and goes is often missed by a single check.")
    comparison_note = None
    if data["speed"] and not (data["settings"].get("plan_download_mbps")):
        comparison_note = "Set your plan speed in Settings and I can compare your result with what you pay for."
    if comparison_note:
        paragraphs.append(comparison_note)

    unknown = freshness_unknowns(data)
    if not data["speed"]:
        unknown.append("No speed test has been saved, so download and upload speed are unknown.")
    if router_ok is False and not router_slow:
        unknown.append("The router delay was not measured, so I cannot tell whether the slowness is inside or beyond your network.")
    unknown.append("Which device or website feels slow, and at what time, since a single check shows one moment only.")
    unknown.append("Whether other devices on the network are using a lot of the connection right now.")

    tests, fixes = tests_and_fixes(causes, ["Run the Network Doctor and a speed test at the time it feels slow."])
    if is_hotspot(data):
        fixes = [f for f in fixes if "modem or router" not in f]
    return {
        "title": "Why is it slow", "understood_as": understood, "paragraphs": paragraphs,
        "measured": measured, "causes": causes.output(), "unknown": unknown, "tests": tests, "fixes": fixes,
        "sources": source_lines(data, {"results", "speed", "history", "settings"}), "safety": SAFETY,
    }


def drop_numbers(samples, events):
    total = len(samples)
    internet_down = [s for s in samples if s.get("internet_ok") is False]
    router_up_internet_down = [s for s in internet_down if s.get("router_online")]
    router_down = [s for s in internet_down if not s.get("router_online")]
    lost_events = [e for e in events if e.get("message") in ("Internet connection lost", "Connection lost")]
    wifi_events = [e for e in events if e.get("message") == "Wi-Fi disconnected"]
    gap_events = [e for e in events if str(e.get("message", "")).startswith("No monitoring")]
    return total, internet_down, router_up_internet_down, router_down, lost_events, wifi_events, gap_events


def answer_drops(data):
    understood = UNDERSTOOD["drops"]
    samples, events = data["samples"], data["events"]
    if not samples:
        answer = empty_answer("Does the connection drop", understood)
        answer["paragraphs"] = ["There is no monitoring history yet, so I cannot tell whether your connection drops. "
                                "Monitoring takes a light sample every few minutes while the server is running and the computer is awake."]
        answer["unknown"] = ["Whether the connection has dropped: nothing has been recorded."]
        answer["tests"] = ["Leave python scrtncl_server.py running, and ask again later.",
                           "Check in Settings that background monitoring is turned on."]
        return answer

    total, down, only_internet, router_down, lost, wifi_lost, gaps = drop_numbers(samples, events)
    span = coverage(samples)
    interval = data["history"].get("interval_minutes", 5)
    measured = [plural(total, "monitoring sample") + " over " + span + ", about one every " + str(interval) + " minutes.",
                "Reachable: " + str(percent(total - len(down), total)) + "% of samples. Not reachable: " + plural(len(down), "sample") + "."]
    if lost:
        measured.append(plural(len(lost), "connection loss event") + " recorded in the History events.")
    if wifi_lost:
        measured.append(plural(len(wifi_lost), "Wi-Fi disconnect") + " recorded.")
    if gaps:
        measured.append(plural(len(gaps), "gap") + " with no monitoring (computer asleep or server stopped), so those periods are unknown.")

    causes = Causes()
    if only_internet:
        evidence = [plural(len(only_internet), "sample") + " had a router that answered but no internet."]
        if lost:
            evidence.append("The History events show " + plural(len(lost), "internet loss") + ".")
        if len(only_internet) >= 3:
            evidence.append("It happened in several separate samples, not just once.")
        causes.add("internet_drop", "The drops happen beyond your router, at the modem, your provider, or the line", evidence)
    if router_down:
        evidence = [plural(len(router_down), "sample") + " had neither the router nor the internet answering."]
        online_wifi = [s for s in router_down if s.get("wifi_connected")]
        if online_wifi:
            evidence.append("This computer was still on Wi-Fi in " + str(len(online_wifi)) + " of them, so the router itself may have stopped answering.")
        causes.add("local_drop", "The router, or this computer's link to it, stops answering at times", evidence)
    if wifi_lost:
        evidence = [plural(len(wifi_lost), "Wi-Fi disconnect") + " recorded."]
        signals_down = values_of(down, "wifi_signal")
        signals_ok = values_of([s for s in samples if s.get("internet_ok")], "wifi_signal")
        if signals_down and signals_ok and statistics.mean(signals_down) < statistics.mean(signals_ok) - 10:
            evidence.append("The signal was weaker during drops (" + str(round(statistics.mean(signals_down))) +
                            "% on average, against " + str(round(statistics.mean(signals_ok))) + "% otherwise).")
        causes.add("wifi_drop", "The Wi-Fi connection itself drops", evidence)

    paragraphs = []
    if down or lost or wifi_lost:
        paragraphs.append("Yes, the monitoring history shows the connection dropping. See the numbers and the most likely cause in the Findings panel.")
    else:
        paragraphs.append("No drops were recorded in the monitoring history over " + span + ". "
                          "That does not rule out short drops, because a sample is taken only every " + str(interval) + " minutes.")

    unknown = [
        "Drops shorter than " + str(interval) + " minutes can fall between two samples and be missed.",
        "Anything while the computer was asleep or the server was not running.",
        "Whether other devices on the network dropped too.",
    ]
    unknown += freshness_unknowns(data)[:1]
    tests, fixes = tests_and_fixes(causes, ["Keep the server running so the History panel can show a longer record."])
    if is_hotspot(data):
        fixes = [f for f in fixes if "modem or router" not in f and "router's power" not in f]
    return {
        "title": "Does the connection drop", "understood_as": understood, "paragraphs": paragraphs,
        "measured": measured, "causes": causes.output(), "unknown": unknown, "tests": tests, "fixes": fixes,
        "sources": source_lines(data, {"history"}), "safety": SAFETY,
    }


def answer_wifi(data):
    understood = UNDERSTOOD["wifi"]
    wifi = data["metrics"].get("wifi") or {}
    if not data["results"] and not data["samples"]:
        return empty_answer("How is the Wi-Fi", understood)

    measured, unknown, causes = [], freshness_unknowns(data), Causes()
    paragraphs = []
    if wifi.get("connected"):
        parts = ["Signal " + str(wifi.get("signal_percent")) + "% (about " + str(wifi.get("signal_dbm")) + " dBm)"]
        if wifi.get("band"):
            parts.append(str(wifi["band"]))
        if wifi.get("channel"):
            parts.append("channel " + str(wifi["channel"]))
        if wifi.get("rx_mbps"):
            parts.append("link speed " + str(round(wifi["rx_mbps"])) + " Mbps")
        measured.append("Wi-Fi link: " + ", ".join(parts) + " (rated " + str(rating(data, "wifi")) + ").")
        history = values_of(data["samples"], "wifi_signal")
        if len(history) >= 6:
            measured.append("Signal in the monitoring history: average " + str(round(statistics.mean(history))) + "%, lowest " + str(round(min(history))) + "%.")
        measured += measured_lines(data, ["router_delay"])

        weak = rating(data, "wifi") in ("fair", "poor")
        router_slow = rating(data, "router_delay") in ("fair", "poor")
        if weak:
            evidence = ["Signal is " + str(wifi.get("signal_percent")) + "%, rated " + str(rating(data, "wifi")) + "."]
            if router_slow:
                evidence.append("Router replies are slow: " + str(item_text(data, "router_delay")) + ".")
            if len(history) >= 6 and statistics.mean(history) < 70:
                evidence.append("The average signal over time is also low (" + str(round(statistics.mean(history))) + "%).")
            causes.add("wifi", "The Wi-Fi signal is weak", evidence)
            paragraphs.append("Your Wi-Fi signal is on the weak side, which often causes slow speeds and dropped connections.")
        elif router_slow:
            causes.add("router", "The signal is fine but the router is slow to answer, which can mean interference or a busy router",
                       ["Signal is " + str(wifi.get("signal_percent")) + "%, rated " + str(rating(data, "wifi")) + ".",
                        "Router replies are slow: " + str(item_text(data, "router_delay")) + "."])
            paragraphs.append("Your signal is good, but the router is answering slowly.")
        else:
            paragraphs.append("Your Wi-Fi looks healthy in the saved data: the signal is " + str(rating(data, "wifi")) + " and nothing points to a Wi-Fi problem.")
        unknown.append("If you connect through an extender, the signal shown is the link to the extender, not to the main router.")
        unknown.append("Interference from nearby networks, because scrtncl does not scan for other Wi-Fi networks.")
    else:
        reason = wifi.get("reason") or "No Wi-Fi details were available."
        measured.append("Wi-Fi: " + str(reason))
        paragraphs.append("I have no Wi-Fi reading for this computer. It may be on a cable, or the Wi-Fi details could not be read.")
        unknown.append("Wi-Fi readings work on English Windows and Linux only, not macOS.")

    tests, fixes = tests_and_fixes(causes, ["Run the Network Doctor in the room where the Wi-Fi feels poor."])
    return {
        "title": "How is the Wi-Fi", "understood_as": understood, "paragraphs": paragraphs,
        "measured": measured, "causes": causes.output(), "unknown": unknown, "tests": tests, "fixes": fixes,
        "sources": source_lines(data, {"results", "history"}), "safety": SAFETY,
    }


def answer_dns(data):
    understood = UNDERSTOOD["dns"]
    results = data["results"]
    if not results:
        return empty_answer("Is DNS a problem", understood)

    stages = {s["name"]: s for s in results.get("stages", [])}
    dns_stage = stages.get("DNS resolution")
    web_stage = stages.get("Application connectivity")
    external = stages.get("External connectivity")
    measured = []
    for stage in (external, dns_stage, web_stage):
        if stage and stage["status"] != "skip":
            measured.append(stage["name"] + ": " + stage["detail"])
    measured += measured_lines(data, ["dns", "web"])
    history_dns = values_of(data["samples"], "dns_ms")
    if len(history_dns) >= 6:
        measured.append("DNS time in the monitoring history: typically " + str(round(median(history_dns))) + " ms, highest " + str(round(max(history_dns))) + " ms.")

    causes = Causes()
    paragraphs = []
    if dns_stage and dns_stage["status"] == "fail":
        evidence = ["The DNS stage failed: " + dns_stage["detail"]]
        if external and external["status"] == "pass":
            evidence.append("The internet itself can be reached, so the connection is not the problem.")
        if "known working server did answer" in dns_stage["detail"]:
            evidence.append("A known working DNS server did answer, so the problem is the DNS server this computer uses.")
        causes.add("dns", "The DNS server this computer uses is not answering", evidence)
        paragraphs.append("Yes, DNS looks like the problem in the latest check.")
    elif rating(data, "dns") in ("fair", "poor"):
        evidence = ["DNS lookups are slow: " + str(item_text(data, "dns")) + "."]
        if rating(data, "web") in ("fair", "poor"):
            evidence.append("Web pages are slow to load: " + str(item_text(data, "web")) + ".")
        if len(history_dns) >= 6 and median(history_dns) > 150:
            evidence.append("The typical DNS time in the history is also high (" + str(round(median(history_dns))) + " ms).")
        causes.add("dns", "DNS lookups are slow, so pages are slow to start loading", evidence)
        paragraphs.append("DNS works but it is slow, which can make websites feel slow to start.")
    elif web_stage and web_stage["status"] == "fail":
        paragraphs.append("DNS looks fine, but loading a web page failed. That points to a proxy, VPN, certificate, or website problem rather than DNS.")
    elif dns_stage and dns_stage["status"] in ("pass", "warn"):
        paragraphs.append("DNS looks fine in the latest check, so it is probably not the reason a website will not load.")
    else:
        paragraphs.append("The latest check did not test DNS, so I cannot say.")

    unknown = freshness_unknowns(data)
    unknown.append("Whether a VPN, proxy, or filtering rule is involved. These are not checked.")
    unknown.append("Whether one particular website is down. Use the Network Doctor's own-site test to check one.")
    tests, fixes = tests_and_fixes(causes, ["Run the Network Doctor with Choose a site, and type the website that will not load."])
    return {
        "title": "Is DNS a problem", "understood_as": understood, "paragraphs": paragraphs,
        "measured": measured, "causes": causes.output(), "unknown": unknown, "tests": tests, "fixes": fixes,
        "sources": source_lines(data, {"results", "history"}), "safety": SAFETY,
    }


def answer_devices(data):
    understood = UNDERSTOOD["devices"]
    report = data["devices"]
    if not report:
        answer = empty_answer("Who is on the network", understood)
        answer["paragraphs"] = ["No device scan has been saved yet. Open the Device Manager and press Scan network, then ask again."]
        answer["unknown"] = ["Which devices are on the network: no scan has been run."]
        answer["tests"] = ["Open the Device Manager and press Scan network."]
        return answer

    devices = report.get("devices", [])
    online = [d for d in devices if d.get("status") == "online"]
    offline = [d for d in devices if d.get("status") != "online"]
    new = [d for d in devices if d.get("is_new")]
    unnamed = [d for d in online if not (d.get("custom_name") or d.get("hostname")) and d.get("kind") == "Unknown"]
    private = [d for d in online if d.get("private_mac")]

    def label(device):
        name = device.get("custom_name") or device.get("hostname") or "(no name shared)"
        return name + ", " + str(device.get("ip")) + (", " + str(device["mac"]) if device.get("mac") else "")

    measured = [plural(len(online), "device") + " answered in the scan of " + str(report.get("network")) + " (" + ago(report.get("time")) + ").",
                plural(len(offline), "remembered device") + " did not answer this time."]
    if unnamed:
        measured.append(plural(len(unnamed), "online device") + " share no name and have no name from you.")
    if private:
        measured.append(plural(len(private), "device") + " use a private (made-up) MAC address, as many phones and laptops do.")
    for device in new[:6]:
        measured.append("New and not marked as known: " + label(device) + ".")

    paragraphs = []
    if new:
        paragraphs.append(plural(len(new), "device") + " appeared recently and " + ("has" if len(new) == 1 else "have") +
                          " not been marked as known. That is not proof of anything wrong; new phones, guests, and smart devices show up like this.")
    else:
        paragraphs.append("No new, unreviewed devices were found in the last scan.")

    unknown = ["A scan only sees devices that answered a ping or appeared in this computer's address table, so sleeping devices can be missing.",
               "Whether any device does not belong. scrtncl can show what is there, but only you know what you own.",
               "What a device is, when it shows no name. Check its MAC address against your own devices."]
    if report.get("time") and (hours_since(report["time"]) or 0) > STALE_HOURS:
        unknown.insert(0, "The scan is " + ago(report["time"]) + ", so devices may have joined or left since.")
    tests = ["Press Scan network again in the Device Manager for a fresh list.",
             "Switch your own devices off Wi-Fi one at a time, rescan, and see which entry goes offline."]
    fixes = ["Give each device you recognise a name and mark it as known in the Device Manager."]
    if new:
        fixes.append("If you cannot identify a device, change your Wi-Fi password in the router settings and reconnect your own devices.")
    return {
        "title": "Who is on the network", "understood_as": understood, "paragraphs": paragraphs,
        "measured": measured, "causes": [], "unknown": unknown, "tests": tests, "fixes": fixes,
        "sources": source_lines(data, {"devices"}), "safety": SAFETY,
    }


def answer_status(data, understood=None):
    understood = understood or UNDERSTOOD["status"]
    if no_data(data):
        return empty_answer("Is the internet working", understood)

    samples = data["samples"]
    last_sample = samples[-1] if samples else None
    results = data["results"]
    measured, paragraphs = [], []

    newest_is_sample = last_sample and (not results or (last_sample.get("t", "") >= results.get("time", "")))
    if newest_is_sample:
        s = last_sample
        if s.get("internet_ok"):
            paragraphs.append("Yes. The latest monitoring sample (" + ago(s["t"]) + ") reached the internet.")
        elif s.get("router_online"):
            paragraphs.append("Not at the moment. The latest sample (" + ago(s["t"]) + ") reached your router but not the internet, so the problem is beyond your router.")
        else:
            paragraphs.append("Not at the moment. In the latest sample (" + ago(s["t"]) + ") neither your router nor the internet answered.")
        measured.append("Router: " + ("answering" + (", " + str(s["router_ms"]) + " ms" if s.get("router_ms") is not None else "") if s.get("router_online") else "not answering") + ".")
        measured.append("Internet: " + ("reachable" + (", " + str(s["internet_ms"]) + " ms" if s.get("internet_ms") is not None else "") if s.get("internet_ok") else "not reachable") + ".")
        if s.get("dns_ms") is not None:
            measured.append("DNS lookup: " + str(s["dns_ms"]) + " ms.")
    elif results:
        diagnosis = (results.get("diagnosis") or {}).get("title", "unknown")
        paragraphs.append("The latest Network Doctor check (" + ago(results.get("time")) + ") says: " + diagnosis + ".")
        for stage in results.get("stages", []):
            if stage["status"] != "skip":
                measured.append(stage["name"] + " (" + stage["status"] + "): " + stage["detail"])

    quality = data["quality"]
    if quality and quality.get("label") != "Offline":
        paragraphs.append("Overall quality from your measurements: " + str(quality["overall"]) + ". " + quality["summary"])

    unknown = freshness_unknowns(data)
    unknown.append("Anything after the last check or sample: this is not a live test.")
    unknown.append("Whether a particular website or device is affected.")
    tests = ["Press Check now on the Overview, or run the Network Doctor, for a live result."]
    return {
        "title": "Is the internet working", "understood_as": understood, "paragraphs": paragraphs,
        "measured": measured, "causes": [], "unknown": unknown, "tests": tests, "fixes": [],
        "sources": source_lines(data, {"results", "history", "speed"}), "safety": SAFETY,
    }


# ---------------------------------------------------------------
# Choosing what the question is about
# ---------------------------------------------------------------

def detect_intent(question):
    text = question.lower().replace("wi-fi", "wifi").replace("wi fi", "wifi")
    best, best_score = None, 0
    for intent in INTENT_ORDER:
        score = 0
        for word in INTENT_WORDS[intent]:
            if re.search(r"(?<![a-z])" + re.escape(word) + r"(?![a-z])", text):
                score += 1
        if score > best_score:
            best, best_score = intent, score
    return best


def answer(question):
    """Answer one question from the saved data. Never runs a test and never changes anything."""
    data = gather()
    intent = detect_intent(question)
    handlers = {"slow": answer_slow, "drops": answer_drops, "wifi": answer_wifi,
                "dns": answer_dns, "devices": answer_devices}
    if intent in handlers:
        result = handlers[intent](data)
    elif intent == "status":
        result = answer_status(data)
    else:
        result = answer_status(data, "I was not sure what you meant, so here is the general state of your connection. "
                                     "You can ask about slowness, drops, Wi-Fi, DNS, or devices.")
    text = question.lower()
    if re.search(r"\b(change|reset|fix it for me|turn off|turn on|reboot|restart it for me|block)\b", text):
        result["paragraphs"].append("I can't change anything on your router or network. I only read your saved data, "
                                    "so any fix I list is for you to try yourself.")
    return result


if __name__ == "__main__":
    import json
    ask = " ".join(sys.argv[1:]) or "Is my internet working right now?"
    print(json.dumps(answer(ask), indent=2))
