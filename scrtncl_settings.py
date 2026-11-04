"""
scrtncl settings.

Settings are saved on this computer in scrtncl-settings.json, next to the
server. The server checks every value before saving, so a bad value is
replaced with its default instead of breaking anything.

Some settings are used right now (background monitoring, alerts, plan
speed). Others are saved for features that come later (modes, privacy,
safety rules for router changes).
"""

import json
import os

FOLDER = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(FOLDER, "scrtncl-settings.json")

DEFAULTS = {
    # saved for later
    "mode": "simple",
    "network_type": "home",
    "safe_readonly": True,
    "safe_confirm": True,
    "safe_backup": True,
    "safe_verify": True,
    "share_results": True,
    "share_logs": False,
    "ai_where": "cloud",
    # used now
    "alert_offline": True,
    "alert_new_device": True,
    "alert_connection": True,
    "alert_wifi": True,
    "monitor_enabled": True,
    "monitor_minutes": 5,
    "plan_download_mbps": None,
    "plan_upload_mbps": None,
}

CHOICES = {
    "mode": ("simple", "technician"),
    "network_type": ("home", "office"),
    "ai_where": ("cloud", "local"),
    "monitor_minutes": (1, 2, 5, 10, 15, 30, 60),
}

MAX_PLAN_MBPS = 100000


def clean(values):
    """Return a complete, valid settings dictionary built from `values`."""
    values = values if isinstance(values, dict) else {}
    result = dict(DEFAULTS)
    for key, default in DEFAULTS.items():
        if key not in values:
            continue
        value = values[key]
        if key in CHOICES:
            if value in CHOICES[key] and not isinstance(value, bool):
                result[key] = value
        elif isinstance(default, bool):
            if isinstance(value, bool):
                result[key] = value
        elif key.startswith("plan_"):
            if value in (None, ""):
                result[key] = None
            elif isinstance(value, (int, float)) and not isinstance(value, bool) and 0 < value <= MAX_PLAN_MBPS:
                result[key] = round(float(value), 1)
    return result


def load_settings(path=SETTINGS_FILE):
    try:
        with open(path, encoding="utf-8") as file:
            return clean(json.load(file))
    except (OSError, ValueError):
        return dict(DEFAULTS)


def save_settings(values, path=SETTINGS_FILE):
    saved = clean(values)
    with open(path, "w", encoding="utf-8") as file:
        json.dump(saved, file, indent=2)
    return saved
