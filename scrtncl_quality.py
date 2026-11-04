"""
scrtncl engine: connection quality.

Turns the numbers from the checks and the speed test into plain ratings
(excellent, good, fair, poor) plus an overall verdict and a short list of
what the connection is good enough for.

The thresholds below are rules of thumb for home and small office use.
They are not official standards, and they can be adjusted.
"""

import json
import os

FOLDER = os.path.dirname(os.path.abspath(__file__))
RESULTS_FILE = os.path.join(FOLDER, "scrtncl-results.json")

SCORES = {"poor": 0, "fair": 1, "good": 2, "excellent": 3}
NAMES = ["poor", "fair", "good", "excellent"]

# (excellent, good, fair): anything worse than "fair" is poor.
THRESHOLDS = {
    "download": (100, 25, 10),     # Mbps, higher is better
    "upload": (20, 5, 2),          # Mbps, higher is better
    "internet_delay": (30, 60, 120),   # ms, lower is better
    "busy_delay": (30, 100, 200),      # extra ms while downloading, lower is better
    "router_delay": (5, 20, 50),       # ms, lower is better
    "dns": (50, 150, 400),             # ms, lower is better
    "web": (300, 800, 2000),           # ms, lower is better
    "wifi": (85, 70, 40),              # signal percent, higher is better
}

# Share of your plan speed that counts as excellent, good, or fair.
PLAN_THRESHOLDS = (80, 60, 40)

WEAK_SPOT_TEXT = {
    "download": "slow download speed",
    "upload": "slow upload speed",
    "internet_delay": "high delay to the internet",
    "busy_delay": "delay that jumps when the connection is busy",
    "router_delay": "slow replies from your router",
    "dns": "slow DNS lookups",
    "web": "slow web page loading",
    "wifi": "a weak Wi-Fi signal",
}


def rate_high(value, limits):
    excellent, good, fair = limits
    if value >= excellent:
        return "excellent"
    if value >= good:
        return "good"
    if value >= fair:
        return "fair"
    return "poor"


def rate_low(value, limits):
    excellent, good, fair = limits
    if value <= excellent:
        return "excellent"
    if value <= good:
        return "good"
    if value <= fair:
        return "fair"
    return "poor"


def load_results():
    try:
        with open(RESULTS_FILE, encoding="utf-8") as file:
            return json.load(file)
    except (OSError, ValueError):
        return None


def number(value):
    return value if isinstance(value, (int, float)) else None


def build_items(metrics, speed, settings=None):
    """Return a list of rated measurements. rating is None when not measured."""
    items = []

    def add(key, label, value, text, rating):
        items.append({"key": key, "label": label, "value": text if value is not None else "Not measured",
                      "rating": rating if value is not None else None})

    download = number(speed.get("download_mbps"))
    upload = number(speed.get("upload_mbps"))
    idle = number(speed.get("idle_delay_ms"))
    loaded = number(speed.get("loaded_delay_ms"))
    if idle is None:
        idle = number(metrics.get("internet_ms"))
    busy = loaded - idle if loaded is not None and idle is not None else None
    wifi = metrics.get("wifi") or {}
    signal = number(wifi.get("signal_percent")) if wifi.get("connected") else None

    settings = settings or {}
    plan_down = number(settings.get("plan_download_mbps"))
    plan_up = number(settings.get("plan_upload_mbps"))

    # With a plan speed set, speed is judged against what you pay for.
    if download is not None and plan_down:
        percent = round(download / plan_down * 100)
        add("download", "Download speed", download, str(download) + " Mbps (" + str(percent) + "% of your plan)",
            rate_high(percent, PLAN_THRESHOLDS))
        items[-1]["plan"] = True
    else:
        add("download", "Download speed", download, str(download) + " Mbps",
            rate_high(download, THRESHOLDS["download"]) if download is not None else None)
    if upload is not None and plan_up:
        percent = round(upload / plan_up * 100)
        add("upload", "Upload speed", upload, str(upload) + " Mbps (" + str(percent) + "% of your plan)",
            rate_high(percent, PLAN_THRESHOLDS))
        items[-1]["plan"] = True
    else:
        add("upload", "Upload speed", upload, str(upload) + " Mbps",
            rate_high(upload, THRESHOLDS["upload"]) if upload is not None else None)
    add("internet_delay", "Delay to the internet", idle, str(round(idle)) + " ms" if idle is not None else "",
        rate_low(idle, THRESHOLDS["internet_delay"]) if idle is not None else None)
    add("busy_delay", "Extra delay when busy", busy, "+" + str(max(0, round(busy))) + " ms" if busy is not None else "",
        rate_low(max(busy, 0), THRESHOLDS["busy_delay"]) if busy is not None else None)
    router = number(metrics.get("router_ms"))
    add("router_delay", "Delay to your router", router, str(router) + " ms" if router is not None else "",
        rate_low(router, THRESHOLDS["router_delay"]) if router is not None else None)
    dns = number(metrics.get("dns_ms"))
    add("dns", "DNS lookups", dns, str(dns) + " ms" if dns is not None else "",
        rate_low(dns, THRESHOLDS["dns"]) if dns is not None else None)
    web = number(metrics.get("web_ms"))
    add("web", "Web page load", web, str(web) + " ms" if web is not None else "",
        rate_low(web, THRESHOLDS["web"]) if web is not None else None)
    add("wifi", "Wi-Fi signal", signal, str(round(signal)) + "%" if signal is not None else "",
        rate_high(signal, THRESHOLDS["wifi"]) if signal is not None else None)
    return items


def overall_rating(items):
    rated = [item for item in items if item["rating"] is not None]
    if not rated:
        return None
    mean = sum(SCORES[item["rating"]] for item in rated) / len(rated)
    if mean >= 2.5:
        overall = "excellent"
    elif mean >= 1.75:
        overall = "good"
    elif mean >= 1.0:
        overall = "fair"
    else:
        overall = "poor"
    # One poor measurement keeps the verdict from being better than fair.
    if any(item["rating"] == "poor" for item in rated) and SCORES[overall] > SCORES["fair"]:
        overall = "fair"
    # Excellent overall needs every measurement to be at least good.
    if overall == "excellent" and any(item["rating"] == "fair" for item in rated):
        overall = "good"
    return overall


def judge_uses(speed, metrics, items):
    """Rough 'good enough for' checks. Each is fine, borderline, struggles, or None."""
    values = {item["key"]: item for item in items}

    def raw(name):
        return number(speed.get(name))

    download, upload = raw("download_mbps"), raw("upload_mbps")
    idle = raw("idle_delay_ms")
    if idle is None:
        idle = number(metrics.get("internet_ms"))
    loaded = raw("loaded_delay_ms")
    busy = loaded - idle if loaded is not None and idle is not None else None
    dns, web = number(metrics.get("dns_ms")), number(metrics.get("web_ms"))

    def pick(fine, struggles):
        return "fine" if fine else "struggles" if struggles else "borderline"

    uses = []

    if dns is not None and web is not None:
        browsing = pick(dns <= 150 and web <= 800, dns > 400 or web > 2000)
    else:
        browsing = None
    uses.append({"label": "Web browsing", "verdict": browsing})

    if download is not None and upload is not None and idle is not None:
        calls = pick(upload >= 3 and download >= 5 and idle <= 100 and (busy is None or busy <= 100),
                     upload < 1 or download < 2 or idle > 200)
    else:
        calls = None
    uses.append({"label": "HD video calls", "verdict": calls})

    uses.append({"label": "HD streaming (1080p)",
                 "verdict": pick(download >= 10, download < 3) if download is not None else None})
    uses.append({"label": "4K streaming",
                 "verdict": pick(download >= 25, download < 10) if download is not None else None})

    if idle is not None:
        gaming = pick(idle <= 50 and (busy is None or busy <= 60), idle > 120 or (busy is not None and busy > 200))
    else:
        gaming = None
    uses.append({"label": "Online gaming", "verdict": gaming})
    return uses


def context_notes(metrics, items):
    notes = []
    gateway = metrics.get("gateway") or ""
    if gateway.startswith("172.20.10."):
        notes.append("Your gateway address (" + gateway + ") is the one iPhones use for Personal Hotspot, "
                     "so you may be on a phone hotspot. On a hotspot, speed and delay depend on your mobile signal.")
    elif gateway.startswith("192.168.43."):
        notes.append("Your gateway address (" + gateway + ") is the one many Android phones use for hotspot, "
                     "so you may be on a phone hotspot. On a hotspot, speed and delay depend on your mobile signal.")

    ratings = {item["key"]: item["rating"] for item in items}
    if ratings.get("router_delay") in ("excellent", "good") and ratings.get("internet_delay") in ("fair", "poor"):
        notes.append("Your router answers quickly but the delay to the internet is high, so the slowness "
                     "is probably beyond your own network, at your provider or mobile signal.")
    if ratings.get("wifi") in ("excellent", "good") and ratings.get("download") in ("fair", "poor"):
        notes.append("Your Wi-Fi signal is fine, so slow downloads are probably not caused by Wi-Fi.")
    return notes


def assess(results, speed, settings=None):
    """Build the quality summary from the saved check results and speed test."""
    metrics = (results or {}).get("metrics") or {}
    speed = speed if speed and speed.get("ok") else {}

    # No connection right now: an old speed test would be misleading, so ignore it.
    if metrics and metrics.get("internet_ok") is False:
        items = build_items(metrics, {}, settings)
        if metrics.get("router_online"):
            summary = ("Your router answers, but the internet cannot be reached. The problem is probably "
                       "your provider or the router's internet connection.")
        else:
            summary = ("No internet connection was found in the latest check. Check your Wi-Fi or router, "
                       "then press Check now.")
        return {
            "overall": "poor",
            "label": "Offline",
            "summary": summary,
            "items": items,
            "uses": judge_uses({}, metrics, items),
            "notes": ["The speed test from earlier is not used, because there is no connection right now."],
            "checked_at": (results or {}).get("time"),
            "speed_tested_at": None,
        }

    items = build_items(metrics, speed, settings)
    overall = overall_rating(items)
    if overall is None:
        return None

    weak = [item for item in items if item["rating"] in ("poor", "fair")]
    weak.sort(key=lambda item: SCORES[item["rating"]])
    if weak:
        names = [("download speed below your plan" if item["key"] == "download" and item.get("plan")
                  else "upload speed below your plan" if item["key"] == "upload" and item.get("plan")
                  else WEAK_SPOT_TEXT[item["key"]]) for item in weak[:3]]
        summary = "What is holding it back: " + ", ".join(names) + "."
    elif overall == "excellent":
        summary = "Everything that was measured looks great."
    else:
        summary = "Nothing serious is holding it back."

    notes = context_notes(metrics, items)
    missing = [item["label"] for item in items if item["rating"] is None]
    if not speed:
        notes.append("Run a speed test for a fuller rating.")
    elif missing:
        notes.append("Not measured: " + ", ".join(missing) + ".")

    return {
        "overall": overall,
        "summary": summary,
        "items": items,
        "uses": judge_uses(speed, metrics, items),
        "notes": notes,
        "checked_at": (results or {}).get("time"),
        "speed_tested_at": speed.get("time") if speed else None,
    }
