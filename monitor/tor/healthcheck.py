"""Local, cookie-authenticated readiness check; never prints the cookie."""

from pathlib import Path
import re
import socket
import sys


def command(stream, value):
    stream.write(value + b"\r\n")
    stream.flush()
    lines = []
    for _ in range(32):
        line = stream.readline(8193)
        if len(line) > 8192 or not line.endswith(b"\r\n") or not line.startswith(b"250"):
            raise ValueError("Tor control command failed.")
        lines.append(line.rstrip(b"\r\n"))
        if line.startswith(b"250 "):
            return lines
        if not line.startswith(b"250-"):
            raise ValueError("Unexpected Tor control response.")
    raise ValueError("Tor control response exceeded its limit.")


def ready():
    cookie = Path("/var/lib/tor/control.authcookie").read_bytes()
    if len(cookie) != 32:
        return False
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(3)
        channel.connect("/var/lib/tor/control.sock")
        with channel.makefile("rwb") as stream:
            command(stream, b"AUTHENTICATE " + cookie.hex().encode("ascii"))
            lines = command(stream, b"GETINFO status/bootstrap-phase status/circuit-established")
            bootstrapped = any(line.startswith(b"250-status/bootstrap-phase=")
                and re.search(rb"\bPROGRESS=100(?:\s|$)", line) for line in lines)
            circuit = b"250-status/circuit-established=1" in lines
            return bool(bootstrapped and circuit)


if __name__ == "__main__":
    try:
        healthy = ready()
    except (OSError, ValueError):
        healthy = False
    print("Tor ready" if healthy else "Tor is not ready; inspect its bootstrap logs.")
    sys.exit(0 if healthy else 1)
