"""
scrtncl: read-only router probe.

Looks at your router's web page from the outside, the way a browser does
before you log in. It tells us what kind of login the router uses, so the
Router Center can be built to match.

What it does:
  - checks whether a few common ports answer (web, secure web, SSH, Telnet)
  - asks for the router's front page on port 80 and port 443 (GET only)
  - reports the status, any redirect, the server name, the page title, and
    whether the page has a password box

What it never does:
  - it never logs in, never sends a username or password, never changes anything
  - it only talks to private network addresses (your own network)
  - it does not turn off certificate checking. A router's own certificate
    usually is not trusted, and the probe just reports that.

Run it with:   python probe_router.py              (uses your router's address)
or:            python probe_router.py 192.168.100.1
"""

import http.client
import ipaddress
import re
import socket
import ssl
import sys

PORTS = [(80, "web (HTTP)"), (443, "secure web (HTTPS)"), (22, "SSH"), (23, "Telnet"), (8080, "web, alternate")]


def check_address(text):
    """Return the address if it is a private network address, otherwise raise ValueError."""
    try:
        address = ipaddress.ip_address(text.strip())
    except ValueError:
        raise ValueError("That is not a valid address.")
    if address.version != 4 or not address.is_private:
        raise ValueError("Only private network addresses (like 192.168.x.x or 10.x.x.x) are allowed.")
    return str(address)


def port_open(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def look_at_page(host, port, secure):
    """GET the front page once. Returns a dictionary of what was seen."""
    seen = {"reached": False, "note": None}
    try:
        if secure:
            connection = http.client.HTTPSConnection(host, port, timeout=5)
        else:
            connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.request("GET", "/", headers={"User-Agent": "scrtncl-probe/0.1"})
        response = connection.getresponse()
        body = response.read(30000).decode("utf-8", errors="replace")
        connection.close()
    except ssl.SSLCertVerificationError:
        seen["note"] = ("The router answered, but its certificate is not trusted by this computer. "
                        "That is normal for routers that use their own certificate.")
        return seen
    except Exception as error:
        seen["note"] = "No page: " + (str(error) or error.__class__.__name__)
        return seen

    seen["reached"] = True
    seen["status"] = response.status
    seen["redirect"] = response.getheader("Location")
    seen["server"] = response.getheader("Server")
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    seen["title"] = " ".join(title.group(1).split())[:80] if title else None
    seen["password_box"] = bool(re.search(r"type\s*=\s*[\"']?password", body, re.IGNORECASE))
    seen["frames_or_scripts"] = bool(re.search(r"<frame|<iframe|<script", body, re.IGNORECASE))
    return seen


def find_gateway():
    """Use scrtncl's own gateway finder when it is available."""
    try:
        import scrtncl_doctor
        return scrtncl_doctor.get_gateway()
    except Exception:
        return None


def main():
    if len(sys.argv) > 1:
        text = sys.argv[1]
    else:
        text = find_gateway()
        if text:
            print("Found your router address: " + text)
        else:
            text = input("Router address (for example 192.168.100.1): ")
    try:
        host = check_address(text)
    except ValueError as error:
        print(str(error))
        return

    print("\nscrtncl router probe (read-only, no login) for " + host + "\n")

    print("Ports:")
    for port, label in PORTS:
        print("  " + str(port).ljust(5) + label.ljust(22) + ("open" if port_open(host, port) else "closed"))

    for port, secure in ((80, False), (443, True)):
        print("\nFront page on port " + str(port) + ":")
        seen = look_at_page(host, port, secure)
        if not seen["reached"]:
            print("  " + (seen["note"] or "No answer."))
            continue
        print("  Status:        " + str(seen["status"]))
        if seen["redirect"]:
            print("  Redirects to:  " + seen["redirect"])
        print("  Server:        " + (seen["server"] or "not stated"))
        print("  Page title:    " + (seen["title"] or "none"))
        print("  Password box:  " + ("yes" if seen["password_box"] else "not in the first page"))
        print("  Uses scripts or frames: " + ("yes" if seen["frames_or_scripts"] else "no"))

    print("\nDone. Nothing was changed and nobody was logged in.")
    print("This output has no passwords in it, so it is safe to send to me.")


if __name__ == "__main__":
    main()
