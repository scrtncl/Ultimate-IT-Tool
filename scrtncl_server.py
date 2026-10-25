"""
scrtncl engine, step 3: local server.

Serves the scrtncl pages at http://localhost:8000 and runs the
Network Doctor when a page asks for it.

Safety:
  - It only listens on this computer (127.0.0.1). Other devices on your
    network cannot reach it.
  - It only serves the .html pages and four read-only endpoints:
      /api/doctor   runs the same read-only checks as scrtncl_doctor.py
      /api/results  returns the last saved check report without running anything
      /api/scan     scans your local network for devices (see scrtncl_scan.py)
      /api/devices  returns the last saved device scan without running anything

Run it with:   python scrtncl_server.py      (or: py scrtncl_server.py)
Stop it with:  Ctrl+C
"""

import json
import os
import threading
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import scrtncl_doctor
import scrtncl_scan

HOST = "127.0.0.1"
PORT = 8000
FOLDER = os.path.dirname(os.path.abspath(__file__))
ALLOWED_HOSTS = ["localhost:" + str(PORT), "127.0.0.1:" + str(PORT)]

# Only one diagnosis runs at a time.
run_lock = threading.Lock()


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

        if path == "/":
            self.send_response(302)
            self.send_header("Location", "/network-dashboard.html")
            self.end_headers()
        elif path == "/api/doctor":
            try:
                with run_lock:
                    report = scrtncl_doctor.build_report()
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


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    address = "http://localhost:" + str(PORT)
    print("scrtncl is running.")
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
