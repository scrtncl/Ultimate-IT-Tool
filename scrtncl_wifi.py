"""
scrtncl engine: Wi-Fi link quality.

Reads the Wi-Fi connection this computer is using right now: network
name, signal strength, link speed, band, and channel. Read-only.

Works on:
  - Windows (netsh wlan show interfaces, English Windows)
  - Linux with NetworkManager (nmcli)
Not supported yet: macOS, and Windows in languages other than English.
If the details cannot be read, it says so instead of guessing.
"""

import platform
import re
import subprocess

OS = platform.system()

STANDARDS = {
    "802.11n": "Wi-Fi 4",
    "802.11ac": "Wi-Fi 5",
    "802.11ax": "Wi-Fi 6",
    "802.11be": "Wi-Fi 7",
}


def run(command):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=8).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def not_connected(reason):
    return {"connected": False, "reason": reason}


def guess_band(channel):
    """Work out the band from the channel number when Windows does not say."""
    if channel is None:
        return None
    if 1 <= channel <= 14:
        return "2.4 GHz"
    if 32 <= channel <= 177:
        return "5 GHz"
    return None


def quality_from_percent(percent):
    if percent >= 70:
        return "good"
    if percent >= 40:
        return "fair"
    return "weak"


def to_number(text):
    match = re.search(r"[\d.]+", text or "")
    return float(match.group(0)) if match else None


def build_result(ssid, bssid, standard, channel, band, rx, tx, percent):
    channel_number = int(channel) if channel else None
    return {
        "connected": True,
        "ssid": ssid,
        "bssid": bssid,
        "standard": standard,
        "standard_name": STANDARDS.get((standard or "").lower()),
        "channel": channel_number,
        "band": band or guess_band(channel_number),
        "rx_mbps": rx,
        "tx_mbps": tx,
        "signal_percent": percent,
        # Windows only gives a percentage. This is the usual rough conversion.
        "signal_dbm": round(percent / 2 - 100) if percent is not None else None,
        "quality": quality_from_percent(percent) if percent is not None else None,
    }


def parse_netsh(output):
    """Parse 'netsh wlan show interfaces'. Returns the connected adapter, if any."""
    blocks = []
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "name":
            blocks.append({})
        if blocks:
            blocks[-1][key] = value

    if not blocks:
        return not_connected("No Wi-Fi adapter found.")
    for fields in blocks:
        if fields.get("state", "").lower() == "connected":
            percent = to_number(fields.get("signal"))
            if percent is None:
                return not_connected("Connected to Wi-Fi, but the details could not be read.")
            return build_result(
                fields.get("ssid"),
                fields.get("bssid") or fields.get("ap bssid"),
                fields.get("radio type"),
                fields.get("channel"),
                fields.get("band"),
                to_number(fields.get("receive rate (mbps)")),
                to_number(fields.get("transmit rate (mbps)")),
                int(percent),
            )
    return not_connected("Not connected to Wi-Fi. You may be on a wired connection.")


def parse_nmcli(output):
    """Parse 'nmcli -t -f ACTIVE,SSID,BSSID,CHAN,RATE,SIGNAL dev wifi'."""
    for line in output.splitlines():
        line = line.replace("\\:", "\x00")  # BSSIDs contain escaped colons
        parts = [part.replace("\x00", ":") for part in line.split(":")]
        if len(parts) >= 6 and parts[0] == "yes":
            rate = to_number(parts[4])
            percent = int(to_number(parts[5]) or 0)
            return build_result(parts[1], parts[2], None, parts[3], None, rate, rate, percent)
    return not_connected("Not connected to Wi-Fi. You may be on a wired connection.")


def get_wifi():
    """Return a dictionary describing the current Wi-Fi link."""
    if OS == "Windows":
        output = run(["netsh", "wlan", "show", "interfaces"])
        if not output.strip():
            return not_connected("Wi-Fi details could not be read on this computer.")
        return parse_netsh(output)
    if OS == "Linux":
        output = run(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,RATE,SIGNAL", "dev", "wifi"])
        if not output.strip():
            return not_connected("Wi-Fi details could not be read on this computer.")
        return parse_nmcli(output)
    return not_connected("Wi-Fi details are not supported on this system yet.")


if __name__ == "__main__":
    print(get_wifi())
