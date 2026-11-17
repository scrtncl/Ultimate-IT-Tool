"""
scrtncl engine, step 3: local server.

Serves the scrtncl pages at http://localhost:8000 and runs the
Network Doctor when a page asks for it.

Safety:
  - It only listens on this computer (127.0.0.1). Other devices on your
    network cannot reach it.
  - Requests from other websites are refused, so a web page you happen
    to have open cannot start tests on your computer.
  - It only serves the .html pages and these endpoints:
      /api/doctor   runs the same read-only checks as scrtncl_doctor.py
                    (optional ?scope=all|local|dns and ?site=example.com)
      /api/results  returns the last saved check report without running anything
      /api/scan     scans your local network for devices (see scrtncl_scan.py)
      /api/devices  returns the last saved device scan without running anything
      /api/speed    runs an internet speed test (about 50 MB of data)
      /api/speed-results  returns the last saved speed test without running anything
      /api/quality  rates the last saved check and speed test (nothing is run)
      /api/history  the saved monitoring history and events (nothing is run)
      /api/settings reads your settings, or saves them (POST, from the Settings page)
      /api/status   basic facts about the running engine
      /api/ask      the technician answers a question from your saved data (POST)
      /api/device   saves a device's name, group, and known flag (POST)
      /api/ping     pings one device from the saved list (POST)

Background monitoring takes a light sample every few minutes while the
server runs (see scrtncl_monitor.py). To turn it off, start the server with:
    python scrtncl_server.py --no-monitor

Run it with:   python scrtncl_server.py      (or: py scrtncl_server.py)
Stop it with:  Ctrl+C
"""

import json
import os
import platform
import sys
import threading
import webbrowser
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

FOLDER = os.path.dirname(os.path.abspath(__file__))

# Check that every engine file is in the folder before starting, so a missing
# file gives a clear message instead of a long error.
ENGINE_FILES = ["scrtncl_doctor.py", "scrtncl_monitor.py", "scrtncl_quality.py", "scrtncl_scan.py",
                "scrtncl_settings.py", "scrtncl_speed.py", "scrtncl_technician.py", "scrtncl_wifi.py"]
missing_files = [name for name in ENGINE_FILES if not os.path.exists(os.path.join(FOLDER, name))]
if missing_files:
    print("scrtncl cannot start because these files are not in this folder:")
    for name in missing_files:
        print("  " + name)
    print("Folder: " + FOLDER)
    print("Copy them next to scrtncl_server.py, then run it again.")
    sys.exit(1)

import scrtncl_doctor
import scrtncl_monitor
import scrtncl_quality
import scrtncl_scan
import scrtncl_settings
import scrtncl_speed
import scrtncl_technician

HOST = "127.0.0.1"
PORT = 8000
ALLOWED_HOSTS = ["localhost:" + str(PORT), "127.0.0.1:" + str(PORT)]

# Only one diagnosis runs at a time.
run_lock = threading.Lock()
STARTED = datetime.now().isoformat(timespec="seconds")


class Handler(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FOLDER, **kwargs)

    def send_json(self, status, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Refuse requests that were not meant for this local address.
        if self.headers.get("Host", "") not in ALLOWED_HOSTS:
            self.send_error(403, "Not allowed")
            return

        path = self.path.split("?")[0]

        # Pages on other websites must not be able to start tests.
        if path.startswith("/api/") and self.headers.get("Sec-Fetch-Site") not in (None, "same-origin", "none"):
            self.send_error(403, "Not allowed")
            return

        if path == "/":
            self.send_response(302)
            self.send_header("Location", "/network-dashboard.html")
            self.end_headers()
        elif path == "/api/doctor":
            query = parse_qs(urlparse(self.path).query)
            scope = query.get("scope", ["all"])[0]
            site_text = query.get("site", [""])[0]
            try:
                if scope not in scrtncl_doctor.SCOPES:
                    raise ValueError("Unknown kind of check.")
                site = scrtncl_doctor.clean_site(site_text) if site_text.strip() else None
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
                return
            try:
                with run_lock:
                    report = scrtncl_doctor.build_report(scope, site)
                    # Only the full default check is saved. Smaller or custom checks
                    # would give the Overview and the ratings a partial picture.
                    report["saved"] = scope == "all" and site is None
                    if report["saved"]:
                        scrtncl_doctor.save_report(report)
                self.send_json(200, report)
            except Exception as error:
                self.send_json(500, {"error": str(error)})
        elif path == "/api/results":
            # The most recent saved report, without running new tests.
            try:
                with open(os.path.join(FOLDER, "scrtncl-results.json"), encoding="utf-8") as file:
                    saved = json.load(file)
            except (OSError, ValueError):
                self.send_json(404, {"error": "No results yet"})
            else:
                self.send_json(200, saved)
        elif path == "/api/scan":
            try:
                with run_lock:
                    report = scrtncl_scan.scan()
                self.send_json(200, report)
            except scrtncl_scan.ScanNotAllowed as error:
                self.send_json(400, {"error": str(error)})
            except Exception as error:
                self.send_json(500, {"error": str(error)})
        elif path == "/api/speed":
            try:
                with run_lock:
                    result = scrtncl_speed.run_speed_test()
                    if result["ok"]:
                        scrtncl_speed.save_result(result)
                self.send_json(200, result)
            except Exception as error:
                self.send_json(500, {"error": str(error)})
        elif path == "/api/speed-results":
            saved = scrtncl_speed.load_last_result()
            if saved is None:
                self.send_json(404, {"error": "No speed test yet"})
            else:
                self.send_json(200, saved)
        elif path == "/api/history":
            try:
                hours = int(parse_qs(urlparse(self.path).query).get("hours", ["24"])[0])
            except ValueError:
                hours = 24
            hours = max(1, min(hours, 24 * 14))
            self.send_json(200, scrtncl_monitor.get_history(hours))
        elif path == "/api/settings":
            self.send_json(200, scrtncl_settings.load_settings())
        elif path == "/api/status":
            self.send_json(200, {"version": "0.1", "computer": platform.node(),
                                 "python": platform.python_version(), "started": STARTED,
                                 "monitor": scrtncl_monitor.status()})
        elif path == "/api/quality":
            quality = scrtncl_quality.assess(scrtncl_quality.load_results(), scrtncl_speed.load_last_result(),
                                              scrtncl_settings.load_settings())
            if quality is None:
                self.send_json(404, {"error": "Nothing to rate yet"})
            else:
                self.send_json(200, quality)
        elif path == "/api/devices":
            saved = scrtncl_scan.load_last_report()
            if saved is None:
                self.send_json(404, {"error": "No scan yet"})
            else:
                self.send_json(200, saved)
        elif path.endswith(".html"):
            super().do_GET()
        else:
            self.send_error(404, "Not found")

    def do_POST(self):
        # Only these pages may send data, and only from this computer.
        if self.headers.get("Host", "") not in ALLOWED_HOSTS:
            self.send_error(403, "Not allowed")
            return
        if self.headers.get("Sec-Fetch-Site") not in (None, "same-origin"):
            self.send_error(403, "Not allowed")
            return
        post_path = self.path.split("?")[0]
        if post_path not in ("/api/settings", "/api/ask", "/api/device", "/api/ping", "/api/ping-tool", "/api/port-scan"):
            self.send_error(404, "Not found")
            return
        if "application/json" not in self.headers.get("Content-Type", ""):
            self.send_error(415, "JSON only")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 20000:
            self.send_json(400, {"error": "The request was empty or too large."})
            return
        try:
            values = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self.send_json(400, {"error": "The request was not valid JSON."})
            return
        if post_path in ("/api/device", "/api/ping", "/api/ping-tool", "/api/port-scan"):
            if not isinstance(values, dict):
                self.send_json(400, {"error": "The request was not valid."})
                return
            try:
                if post_path == "/api/device":
                    result = scrtncl_scan.update_device(values.get("id"), values.get("name"),
                                                        values.get("group"), values.get("known"))
                elif post_path == "/api/ping":
                    result = scrtncl_scan.ping_device(values.get("id"))
                elif post_path == "/api/ping-tool":
                    tool = values.get("tool", "ping")
                    host = values.get("host", "")
                    count = values.get("count", 4)
                    if tool == "traceroute":
                        result = scrtncl_scan.traceroute_host(host)
                    else:
                        result = scrtncl_scan.ping_host(host, count)
                else:
                    scan_type = values.get("type", "tcp")
                    if scan_type != "tcp":
                        self.send_json(400, {"error": "UDP scanning is not supported. Select TCP."})
                        return
                    result = scrtncl_scan.port_scan_host(
                        values.get("host", ""),
                        values.get("start", 1),
                        values.get("end", 1024),
                    )
                self.send_json(200, result)
            except (scrtncl_scan.DeviceError, scrtncl_scan.ScanNotAllowed) as error:
                self.send_json(400, {"error": str(error)})
            except Exception as error:
                self.send_json(500, {"error": str(error)})
            return
        if post_path == "/api/ask":
            question = values.get("question") if isinstance(values, dict) else None
            if not isinstance(question, str) or not question.strip() or len(question) > 500:
                self.send_json(400, {"error": "Please type a question of up to 500 characters."})
                return
            try:
                self.send_json(200, scrtncl_technician.answer(question.strip()))
            except Exception as error:
                self.send_json(500, {"error": "The technician could not answer: " + str(error)})
            return
        self.send_json(200, scrtncl_settings.save_settings(values))


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    address = "http://localhost:" + str(PORT)
    print("scrtncl is running.")
    if "--no-monitor" in sys.argv:
        print("Background monitoring is off.")
    else:
        scrtncl_monitor.start(run_lock)
        settings = scrtncl_settings.load_settings()
        if settings["monitor_enabled"]:
            print("Background monitoring is on: a light check every " + str(settings["monitor_minutes"]) +
                  " minutes while this window stays open.")
        else:
            print("Background monitoring is turned off in Settings.")
    print("Open " + address + " in your browser.")
    print("Press Ctrl+C to stop.")
    threading.Timer(1, lambda: webbrowser.open(address)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
