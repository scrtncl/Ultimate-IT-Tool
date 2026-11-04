"""
scrtncl engine: internet speed test.

Measures download speed, upload speed, and how much delay grows while
the connection is busy. It uses the public Cloudflare speed test
servers (speed.cloudflare.com), the same ones behind their web test.

Data use: about 50 MB per test (40 MB down, 10 MB up). It takes about
10 to 25 seconds. Don't run it on a metered or capped connection unless
you are happy to use that data.

Read-only for your network. It only sends test data to the speed server.

Run it on its own with:   python scrtncl_speed.py      (or: py scrtncl_speed.py)
"""

import http.client
import json
import os
import statistics
import threading
import time
from datetime import datetime
from urllib.parse import urlparse

FOLDER = os.path.dirname(os.path.abspath(__file__))
SPEED_FILE = os.path.join(FOLDER, "scrtncl-speed.json")

BASE_URL = "https://speed.cloudflare.com"
HEADERS = {"User-Agent": "scrtncl/0.1"}

DOWNLOAD_STREAMS = 4
DOWNLOAD_BYTES = 10_000_000   # per stream
UPLOAD_STREAMS = 2
UPLOAD_BYTES = 5_000_000      # most each stream will send
UPLOAD_CHUNK = 500_000        # sent one piece at a time, so slow links still finish
UPLOAD_SECONDS = 8            # stop uploading after this long
MAX_SECONDS = 12              # stop a download stream that takes longer than this
CHUNK = 65536
BUFFERBLOAT_MS = 100          # extra delay under load that is worth mentioning


def connect():
    """Open a connection to the speed test server."""
    parts = urlparse(BASE_URL)
    if parts.scheme == "https":
        return http.client.HTTPSConnection(parts.hostname, parts.port, timeout=15)
    return http.client.HTTPConnection(parts.hostname, parts.port, timeout=15)


def delay_sample(connection):
    """Time one tiny request on an open connection, in milliseconds."""
    start = time.time()
    connection.request("GET", "/__down?bytes=0", headers=HEADERS)
    connection.getresponse().read()
    return (time.time() - start) * 1000


def measure_idle_delay(count=6):
    """Delay with nothing else running. The first request is a warm-up."""
    connection = connect()
    try:
        delay_sample(connection)
        samples = [delay_sample(connection) for _ in range(count)]
    finally:
        connection.close()
    return statistics.median(samples)


def delay_while_loaded(stop_event, samples):
    """Keep timing tiny requests until stop_event is set."""
    try:
        connection = connect()
        delay_sample(connection)
        while not stop_event.is_set():
            samples.append(delay_sample(connection))
            time.sleep(0.15)
        connection.close()
    except Exception:
        pass


def short_error(error):
    return str(error) or error.__class__.__name__


def download_stream(counter, errors, index, deadline):
    try:
        connection = connect()
        connection.request("GET", "/__down?bytes=" + str(DOWNLOAD_BYTES), headers=HEADERS)
        response = connection.getresponse()
        while time.time() < deadline:
            data = response.read(CHUNK)
            if not data:
                break
            counter[index] += len(data)
        connection.close()
    except Exception as error:
        errors.append(short_error(error))


def measure_download():
    """Returns (megabits per second, megabytes used, delay under load in ms or None)."""
    counter = [0] * DOWNLOAD_STREAMS
    errors = []
    loaded = []
    stop_event = threading.Event()
    watcher = threading.Thread(target=delay_while_loaded, args=(stop_event, loaded), daemon=True)
    watcher.start()
    time.sleep(0.5)  # let the delay watcher connect first

    start = time.time()
    deadline = start + MAX_SECONDS
    threads = [threading.Thread(target=download_stream, args=(counter, errors, i, deadline), daemon=True)
               for i in range(DOWNLOAD_STREAMS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(MAX_SECONDS + 5)
    elapsed = max(time.time() - start, 0.001)
    stop_event.set()
    watcher.join(3)

    total = sum(counter)
    if total == 0:
        raise RuntimeError("The download test received no data." + (" (" + errors[0] + ")" if errors else ""))
    mbps = total * 8 / elapsed / 1_000_000
    loaded_delay = statistics.median(loaded) if loaded else None
    return mbps, total / 1_000_000, loaded_delay


def upload_stream(results, finished, errors, index, deadline):
    try:
        connection = connect()
        body = bytes(UPLOAD_CHUNK)
        headers = dict(HEADERS, **{"Content-Type": "application/octet-stream"})
        while time.time() < deadline and results[index] < UPLOAD_BYTES:
            connection.request("POST", "/__up", body=body, headers=headers)
            response = connection.getresponse()
            response.read()
            if response.status >= 400:
                raise RuntimeError("The server answered with error " + str(response.status))
            results[index] += UPLOAD_CHUNK
            finished[index] = time.time()
        connection.close()
    except Exception as error:
        errors.append(short_error(error))


def measure_upload():
    """Returns (megabits per second, megabytes used)."""
    results = [0] * UPLOAD_STREAMS
    finished = [0.0] * UPLOAD_STREAMS
    errors = []
    start = time.time()
    deadline = start + UPLOAD_SECONDS
    threads = [threading.Thread(target=upload_stream, args=(results, finished, errors, i, deadline), daemon=True)
               for i in range(UPLOAD_STREAMS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(UPLOAD_SECONDS + 20)
    total = sum(results)
    if total == 0:
        raise RuntimeError("The upload test did not finish." + (" (" + errors[0] + ")" if errors else ""))
    elapsed = max(max(finished) - start, 0.001)
    return total * 8 / elapsed / 1_000_000, total / 1_000_000


def run_speed_test():
    """Run the whole test and return a result dictionary."""
    result = {
        "ok": False,
        "time": datetime.now().isoformat(timespec="seconds"),
        "server": urlparse(BASE_URL).hostname,
        "download_mbps": None,
        "upload_mbps": None,
        "idle_delay_ms": None,
        "loaded_delay_ms": None,
        "data_mb": 0.0,
        "notes": [],
        "error": None,
    }

    try:
        result["idle_delay_ms"] = round(measure_idle_delay())
    except Exception:
        result["error"] = ("Could not reach the speed test server (" + result["server"] +
                           "). Check your internet connection.")
        return result

    try:
        down, megabytes, loaded = measure_download()
        result["download_mbps"] = round(down, 1)
        result["loaded_delay_ms"] = round(loaded) if loaded is not None else None
        result["data_mb"] += megabytes
    except Exception as error:
        result["notes"].append("Download test failed: " + str(error))

    try:
        up, megabytes = measure_upload()
        result["upload_mbps"] = round(up, 1)
        result["data_mb"] += megabytes
    except Exception as error:
        result["notes"].append("Upload test failed: " + str(error))

    result["data_mb"] = round(result["data_mb"], 1)
    result["ok"] = result["download_mbps"] is not None or result["upload_mbps"] is not None

    if result["loaded_delay_ms"] is not None and result["idle_delay_ms"] is not None:
        extra = result["loaded_delay_ms"] - result["idle_delay_ms"]
        if extra > BUFFERBLOAT_MS:
            result["notes"].append(
                "Delay rose by about " + str(extra) + " ms while downloading. When the connection "
                "is busy, calls and games can lag. This is called bufferbloat.")
    if result["ok"]:
        result["notes"].append(
            "Download speed is measured from your computer to the test server, so Wi-Fi, "
            "your router, and your provider all affect it. A single short test can vary.")
    return result


def save_result(result):
    with open(SPEED_FILE, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=2)


def load_last_result():
    try:
        with open(SPEED_FILE, encoding="utf-8") as file:
            return json.load(file)
    except (OSError, ValueError):
        return None


def main():
    print("scrtncl speed test")
    print("This uses about 50 MB of data and takes about 10 to 25 seconds.\n")
    result = run_speed_test()
    save_result(result)
    if not result["ok"]:
        print("Test failed: " + (result["error"] or "; ".join(result["notes"])))
        return
    print("Download:    " + str(result["download_mbps"]) + " Mbps")
    print("Upload:      " + str(result["upload_mbps"]) + " Mbps")
    print("Idle delay:  " + str(result["idle_delay_ms"]) + " ms")
    print("Delay under load: " + str(result["loaded_delay_ms"]) + " ms")
    print("Data used:   " + str(result["data_mb"]) + " MB")
    for note in result["notes"]:
        print("Note: " + note)
    print("\nSaved to scrtncl-speed.json")


if __name__ == "__main__":
    main()
