"""Per-run SOCKS5 routes without global socket/environment monkeypatching.

Credentials remain in private settings and Python memory. Child tools see only
loopback relay addresses. Enabling a route never falls back to a direct socket.
"""

from contextlib import suppress
from dataclasses import dataclass
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import os
from pathlib import Path
import secrets
import select
import shlex
import shutil
import socket
import threading
import time
from urllib.parse import unquote, urlsplit


STAGES = ("discovery", "dns", "capture")
TOR_STAGES = ("discovery", "capture")


def tor_proxy_url():
    """Compose supplies its service name; native users default to local Tor."""
    value = os.environ.get("TYPO_TOR_PROXY_URL", "socks5h://127.0.0.1:9050").strip()
    validate_url(value)
    if urlsplit(value).username is not None:
        raise ValueError("The Tor preset must be a SOCKS5 endpoint without credentials.")
    return value


def resolve_settings(settings):
    """Resolve the preset before queueing, without modifying saved custom URLs."""
    result = {}
    for stage in STAGES:
        row = dict(settings.get(stage, {}))
        if row.get("source", "custom") == "tor":
            if stage not in TOR_STAGES:
                raise ValueError("Tor cannot be used for the UDP DNS stage.")
            row["url"] = tor_proxy_url()
        result[stage] = row
    return result


def direct_environment():
    return {key: value for key, value in os.environ.items()
            if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}


def validate_url(value):
    try:
        if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 33 for c in value):
            raise ValueError
        parsed = urlsplit(value)
        if (parsed.scheme not in {"socks5", "socks5h"} or not parsed.hostname or not parsed.port
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or not 1 <= parsed.port <= 65535):
            raise ValueError
        host = parsed.hostname.encode("idna").decode("ascii")
        # PySocks' UDP association uses an IPv4 outer socket. IPv6 DNS
        # destinations remain supported inside the SOCKS encapsulation.
        if ":" in host:
            raise ValueError
        for credential in (parsed.username, parsed.password):
            # The pinned PySocks encoder uses UTF-8 for its one-byte length
            # fields; reject lengths that it cannot serialize correctly.
            if credential is not None and (not unquote(credential) or len(unquote(credential).encode()) > 127):
                raise ValueError
        if (parsed.username is None) != (parsed.password is None):
            raise ValueError
    except (ValueError, TypeError, UnicodeError):
        raise ValueError("Use socks5h://host:port or socks5h://user:password@host:port; use an IPv4-capable proxy and credentials up to 127 UTF-8 bytes.") from None
    return value


def public_settings(settings):
    result = {}
    for stage in STAGES:
        row = settings.get(stage, {})
        value = row.get("url", "")
        label = "Not configured"
        if value:
            parsed = urlsplit(validate_url(value))
            label = f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
        source = row.get("source", "custom")
        result[stage] = {"enabled": bool(row.get("enabled")), "configured": bool(value), "endpoint": label,
                         "source": source,
                         "custom_configured": bool(row.get("custom_url", value if source == "custom" else ""))}
    return result


def dns_route_key(settings):
    row = settings.get("dns", {})
    return hashlib.sha256(row["url"].encode()).hexdigest() if row.get("enabled") else "direct"


def browser_command(browser, workdir):
    """Keep Chromium's implicit loopback bypass out of monitored page requests."""
    shell = shutil.which("sh")
    if os.name != "posix" or not shell:
        raise ValueError("Proxied browser capture requires the Linux build or a POSIX shell.")
    path = Path(workdir) / "proxy-chromium"
    source = (f"#!{shell}\nexec {shlex.quote(str(browser))} --disable-quic "
              "--proxy-bypass-list='<-loopback>' \"$@\"\n")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        target.write(source)
    return str(path)


@dataclass(repr=False)
class SocksEndpoint:
    url: str

    def __post_init__(self):
        validate_url(self.url)
        try:
            import socks
        except ImportError:
            raise RuntimeError("SOCKS5 support is unavailable. Rebuild the Docker image or install the updated requirements.") from None
        if getattr(socks, "__version__", None) != "1.7.1":
            raise RuntimeError("This proxy adapter requires the pinned PySocks 1.7.1 dependency.")

    def options(self):
        import socks
        parsed = urlsplit(validate_url(self.url))
        return dict(proxy_type=socks.SOCKS5, proxy_addr=parsed.hostname, proxy_port=parsed.port,
                    proxy_rdns=True, proxy_username=unquote(parsed.username) if parsed.username else None,
                    proxy_password=unquote(parsed.password) if parsed.password else None)

    def connect(self, host, port, register):
        import socks
        channel = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            options = self.options()
            channel.set_proxy(options["proxy_type"], options["proxy_addr"], options["proxy_port"], True,
                              options["proxy_username"], options["proxy_password"])
            channel.settimeout(10)
            register(channel)
            channel.connect((host, port))
            return channel
        except OSError:
            channel.close()
            raise OSError("SOCKS5 connection failed; check the proxy, credentials and destination.") from None

    def udp(self):
        import socks
        channel = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            options = self.options()
            channel.set_proxy(options["proxy_type"], options["proxy_addr"], options["proxy_port"], True,
                              options["proxy_username"], options["proxy_password"])
            # PySocks 1.7.1 bind() creates an unbounded TCP control socket.
            # Use its pinned handshake with our own explicitly timed socket.
            socket.socket.bind(channel, ("0.0.0.0", 0))
            control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            channel._proxyconn = control
            control.settimeout(10)
            control.connect((options["proxy_addr"], options["proxy_port"]))
            _, relay = channel._SOCKS5_request(control, b"\x03", ("0.0.0.0", channel.getsockname()[1]))
            # Match PySocks' NAT handling: the UDP relay port belongs to the
            # same reachable host as the SOCKS control connection.
            socket.socket.connect(channel, (control.getpeername()[0], relay[1]))
            channel.proxy_sockname = ("0.0.0.0", 0)
            channel.settimeout(.2)
            return channel
        except OSError:
            channel.close()
            raise OSError("SOCKS5 UDP association failed; the DNS proxy must support UDP ASSOCIATE.") from None


class HttpProxy:
    """Credential-free loopback HTTP proxy over an authenticated SOCKS5 route."""

    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.stop = threading.Event()
        self.slots = threading.BoundedSemaphore(128)
        self.lock = threading.Lock()
        self.connections = set()
        self.handlers = set()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self):
                super().setup()
                self.connection.settimeout(10)
                owner.track(self.connection)
                with owner.lock:
                    owner.handlers.add(threading.current_thread())

            def finish(self):
                try:
                    super().finish()
                finally:
                    with owner.lock:
                        owner.connections.discard(self.connection)
                        owner.handlers.discard(threading.current_thread())

            def log_message(self, *_):
                pass  # URLs and credentials never enter a request log.

            def do_CONNECT(self):
                self.relay(True)

            def do_GET(self):
                self.relay(False)

            do_HEAD = do_POST = do_PUT = do_DELETE = do_OPTIONS = do_PATCH = do_GET

            def relay(self, tunnel):
                self.close_connection = True
                if not owner.slots.acquire(blocking=False):
                    return
                upstream = None
                opening = []
                try:
                    self.connection.settimeout(10)
                    target = urlsplit("//" + self.path if tunnel else self.path)
                    if (not target.hostname or target.username or target.password or target.fragment
                            or (not tunnel and target.scheme != "http")):
                        self.send_error(400, "Invalid proxy destination")
                        return
                    port = target.port or (443 if tunnel else 80)
                    def track(channel):
                        owner.track(channel)
                        opening.append(channel)
                    upstream = owner.endpoint.connect(target.hostname, port, track)
                    with owner.lock:
                        if owner.stop.is_set():
                            return
                        owner.connections.update((self.connection, upstream))
                    if tunnel:
                        self.send_response(200, "Connection established")
                        self.end_headers()
                        self.wfile.flush()
                    else:
                        path = target.path or "/"
                        if target.query:
                            path += "?" + target.query
                        lines = [f"{self.command} {path} HTTP/1.1"]
                        for key, value in self.headers.items():
                            if key.lower() not in {"proxy-authorization", "proxy-connection", "connection"}:
                                lines.append(f"{key}: {value}")
                        lines.extend(("Connection: close", "", ""))
                        upstream.sendall("\r\n".join(lines).encode("iso-8859-1"))
                        # With unbuffered input, request bodies remain on the
                        # socket and can be streamed without parsing/replaying.
                    self.connection.settimeout(1)
                    upstream.settimeout(1)
                    idle_until = time.monotonic() + 120
                    while not owner.stop.is_set() and time.monotonic() < idle_until:
                        ready, _, _ = select.select((self.connection, upstream), (), (), .2)
                        for source in ready:
                            data = source.recv(65536)
                            if not data:
                                return
                            (upstream if source is self.connection else self.connection).sendall(data)
                            idle_until = time.monotonic() + 120
                except (OSError, ValueError):
                    # Close without a synthetic HTTP response: an internal
                    # proxy error must never look like the monitored website.
                    pass
                finally:
                    with owner.lock:
                        owner.connections.discard(self.connection)
                        if upstream is not None:
                            owner.connections.discard(upstream)
                            upstream.close()
                        for channel in opening:
                            owner.connections.discard(channel)
                    owner.slots.release()

            rbufsize = 0

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .2}, daemon=True)
        self.thread.start()

    def track(self, channel):
        with self.lock:
            if self.stop.is_set():
                channel.close()
                raise OSError("Proxy route is closed")
            self.connections.add(channel)

    def environment(self):
        env = direct_environment()
        env.update(HTTP_PROXY=self.url, HTTPS_PROXY=self.url, http_proxy=self.url, https_proxy=self.url,
                   NO_PROXY="", no_proxy="")
        return env

    def close(self):
        self.stop.set()
        self.server.shutdown()
        self.server.server_close()
        with self.lock:
            for channel in self.connections:
                with suppress(OSError):
                    channel.shutdown(socket.SHUT_RDWR)
                channel.close()
            handlers = list(self.handlers)
        self.thread.join(timeout=2)
        deadline = time.monotonic() + 3
        for handler in handlers:
            handler.join(timeout=max(0, deadline - time.monotonic()))


class DnsRelay:
    """One loopback DNS endpoint per real resolver, over SOCKS5 UDP.

    Rewrite transaction IDs while in flight to isolate tool sockets and retries.
    Restore them only for a matching question from the exact upstream resolver.
    Never synthesize NXDOMAIN/NOERROR for transport errors.
    """

    def __init__(self, endpoint, resolver, index):
        self.resolver = str(ipaddress.ip_address(resolver))
        self.local = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.local.bind((f"127.0.0.{index + 2}", 0))
        self.host, self.port = self.local.getsockname()
        self.address = f"{self.host}:{self.port}"
        self.stop = threading.Event()
        self.error = None
        try:
            self.remote = endpoint.udp()
        except BaseException:
            self.local.close()
            raise
        self.pending = {}
        self.thread = threading.Thread(target=self._run, daemon=True, name="proxy-dns")
        self.thread.start()

    @staticmethod
    def question(wire):
        import dns.message
        message = dns.message.from_wire(wire, ignore_trailing=False)
        if len(message.question) != 1:
            raise ValueError("Expected one DNS question")
        question = message.question[0]
        return question.name.canonicalize().to_text(), question.rdtype, question.rdclass

    def _run(self):
        import dns.exception
        try:
            while not self.stop.is_set():
                now = time.monotonic()
                self.pending = {key: value for key, value in self.pending.items() if value[3] > now}
                ready, _, _ = select.select((self.local, self.remote), (), (), .2)
                for channel in ready:
                    try:
                        wire, sender = channel.recvfrom(65535)
                        if len(wire) < 12:
                            continue
                        question = self.question(wire)
                        if channel is self.local:
                            if len(self.pending) >= 4096:
                                continue
                            key = secrets.randbelow(65536)
                            while key in self.pending:
                                key = (key + 1) % 65536
                            self.pending[key] = (sender, wire[:2], question, now + 15)
                            self.remote.sendto(key.to_bytes(2, "big") + wire[2:], (self.resolver, 53))
                        else:
                            if str(ipaddress.ip_address(sender[0])) != self.resolver or sender[1] != 53:
                                continue
                            key = int.from_bytes(wire[:2], "big")
                            previous = self.pending.get(key)
                            if previous and previous[2] == question:
                                self.pending.pop(key)
                                self.local.sendto(previous[1] + wire[2:], previous[0])
                    except (ValueError, TypeError, NotImplementedError, UnicodeError, dns.exception.DNSException):
                        continue
                    except socket.timeout:
                        continue
        except (OSError, ValueError):
            if not self.stop.is_set():
                self.error = "SOCKS5 DNS relay failed; direct fallback is disabled."

    def close(self):
        self.stop.set()
        self.local.close()
        self.remote.close()
        self.thread.join(timeout=2)


class DnsRoutes:
    def __init__(self, endpoint, resolvers, cancel_event=None):
        self.relays = []
        try:
            for index, resolver in enumerate(dict.fromkeys(resolvers)):
                if cancel_event is not None and cancel_event.is_set():
                    raise RuntimeError("Scan stopped while opening its DNS proxy route.")
                self.relays.append(DnsRelay(endpoint, resolver, index))
        except BaseException:
            self.close()
            raise
        self.by_resolver = {row.resolver: row.address for row in self.relays}
        self.ports = {row.host: row.port for row in self.relays}

    def check(self):
        if any(row.error or not row.thread.is_alive() for row in self.relays):
            raise RuntimeError("SOCKS5 DNS relay stopped; no direct DNS fallback was used.")

    def close(self):
        for relay in self.relays:
            relay.close()
