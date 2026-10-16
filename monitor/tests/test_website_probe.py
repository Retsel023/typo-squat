"""Website checks use fake transports and loopback-only HTTP/TCP fixtures."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socketserver
import socket
import threading
import unittest
from unittest.mock import patch

import requests

from typo_monitor.website_probe import WebsiteProbe


class Response:
    def __init__(self, code):
        self.status_code, self.closed = code, False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    @property
    def content(self):
        raise AssertionError("Website preflight must not read the response body")

    def iter_content(self, *args, **kwargs):
        raise AssertionError("Website preflight must not stream response bodies")


class Sessions:
    def __init__(self, get):
        self.get = get
        self.created, self.calls, self.responses = [], [], []
        self.lock = threading.Lock()

    def __call__(self):
        owner = self

        class Session:
            def __init__(self):
                self.trust_env, self.headers, self.closed = True, {}, False
                with owner.lock:
                    owner.created.append(self)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.closed = True

            def get(self, url, **kwargs):
                with owner.lock:
                    owner.calls.append((self, url, kwargs))
                if self.trust_env or kwargs.get("stream") is not True or kwargs.get("allow_redirects") is not False:
                    raise AssertionError("Expected direct, streaming GET without redirects")
                response = owner.get(url, kwargs)
                with owner.lock:
                    owner.responses.append(response)
                return response

        return Session()


class ProbeTests(unittest.TestCase):
    def test_any_http_status_qualifies_without_reading_body_or_following_redirects(self):
        urls = [f"http://site.example/{status}" for status in (200, 301, 403, 404, 500, 503)]
        sessions = Sessions(lambda url, kwargs: Response(int(url.rsplit("/", 1)[1])))
        with patch("typo_monitor.website_probe.requests.Session", sessions):
            result = WebsiteProbe(workers=2).probe(urls)
        self.assertEqual(set(result), set(urls))
        self.assertTrue(all(row["status"] == "http_response" for row in result.values()))
        self.assertEqual({row["http_status"] for row in result.values()}, {200, 301, 403, 404, 500, 503})
        self.assertEqual(len(sessions.created), len(urls))
        self.assertTrue(all(session.closed for session in sessions.created))
        self.assertTrue(all(response.closed for response in sessions.responses))
        self.assertTrue(all(len([call for call in sessions.calls if call[0] is session]) == 1
                            for session in sessions.created), "Different endpoints shared a Session")

    def test_bad_certificate_retries_unverified_with_remaining_budget_and_keeps_diagnostic(self):
        clock = [10]

        def get(url, kwargs):
            if kwargs["verify"]:
                clock[0] = 11.5
                raise requests.exceptions.SSLError("certificate failed")
            return Response(403)

        sessions = Sessions(get)
        with (patch("typo_monitor.website_probe.requests.Session", sessions),
              patch("typo_monitor.website_probe.time.monotonic", side_effect=lambda: clock[0])):
            row = WebsiteProbe(timeout=3, workers=1).probe(["https://site.example:443"])["https://site.example:443"]
        self.assertEqual(row["status"], "http_response")
        self.assertEqual(row["http_status"], 403)
        self.assertFalse(row["tls_verified"])
        self.assertIn("SSLError", row["tls_error"])
        self.assertEqual([call[2]["verify"] for call in sessions.calls], [True, False])
        self.assertEqual([call[2]["timeout"].total for call in sessions.calls], [3, 1.5])
        self.assertEqual(len(sessions.created), 1)

    def test_tls_failure_without_http_stays_uncertain(self):
        def get(url, kwargs):
            raise requests.exceptions.SSLError("TLS handshake failed")

        sessions = Sessions(get)
        with patch("typo_monitor.website_probe.requests.Session", sessions):
            row = WebsiteProbe().probe(["https://site.example:443"])["https://site.example:443"]
        self.assertEqual(row["status"], "unknown")
        self.assertIsNone(row["http_status"])
        self.assertTrue(row["error"].startswith("Website check uncertain: "))
        self.assertIn("SSLError", row["tls_error"])
        self.assertEqual(len(sessions.calls), 2)

    def test_timeout_is_uncertain_and_connection_failure_is_only_no_http_response(self):
        for error, status, prefix in (
            (requests.exceptions.ReadTimeout(), "unknown", "Website check uncertain: "),
            (requests.exceptions.ConnectTimeout(), "unknown", "Website check uncertain: "),
            (requests.exceptions.ConnectionError(), "no_http_response", "No HTTP response: "),
        ):
            with self.subTest(error=type(error).__name__):
                def fail(url, kwargs):
                    raise error
                sessions = Sessions(fail)
                with patch("typo_monitor.website_probe.requests.Session", sessions):
                    row = WebsiteProbe().probe(["http://site.example:80"])["http://site.example:80"]
                self.assertEqual(row["status"], status)
                self.assertIsNone(row["http_status"])
                self.assertTrue(row["error"].startswith(prefix))
                self.assertIn(type(error).__name__, row["error"])

    def test_wrapped_name_resolution_error_is_uncertain_not_a_clean_negative(self):
        def fail(url, kwargs):
            raise requests.exceptions.ConnectionError(socket.gaierror("Fixture name resolution failed"))

        with patch("typo_monitor.website_probe.requests.Session", Sessions(fail)):
            row = WebsiteProbe().probe(["http://site.example:80"])["http://site.example:80"]
        self.assertEqual(row["status"], "unknown")
        self.assertTrue(row["error"].startswith("Website check uncertain: "))

    def test_progress_end_log_includes_run_id_and_coverage_counts(self):
        def get(url, kwargs):
            if url.endswith("/timeout"):
                raise requests.exceptions.ReadTimeout()
            if url.endswith("/closed"):
                raise requests.exceptions.ConnectionError()
            return Response(200)

        probe = WebsiteProbe()
        probe.run_id = "fixture-run"
        with (patch("typo_monitor.website_probe.requests.Session", Sessions(get)),
              self.assertLogs("typo_monitor.website_probe", level="INFO") as logs):
            probe.probe(["http://site.example/ok", "http://site.example/timeout", "http://site.example/closed"])
        self.assertTrue(any("fixture-run" in line and "3/3 checked; 1 HTTP responses, 1 no HTTP response, 1 uncertain" in line
                            for line in logs.output))

    def test_cancellation_keeps_bounded_active_requests_and_never_refills_backlog(self):
        cancel, active = threading.Event(), threading.Event()
        lock, count, errors = threading.Lock(), [0], []

        def get(url, kwargs):
            with lock:
                count[0] += 1
                if count[0] == 2:
                    active.set()
            if not cancel.wait(timeout=3):
                raise RuntimeError("Fixture cancellation did not arrive")
            return Response(200)

        sessions = Sessions(get)
        probe = WebsiteProbe(workers=2)
        probe.cancel_event = cancel

        def run():
            try:
                probe.probe([f"http://site{index}.example:80" for index in range(20)])
            except BaseException as error:
                errors.append(error)

        with patch("typo_monitor.website_probe.requests.Session", sessions):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            try:
                self.assertTrue(active.wait(timeout=1))
            finally:
                cancel.set()
                worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
        self.assertEqual(len(sessions.calls), 2)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], RuntimeError)
        self.assertTrue(all(session.closed for session in sessions.created))
        self.assertTrue(all(response.closed for response in sessions.responses))

    def test_invalid_configuration_or_urls_fail_before_requests(self):
        for kwargs in ({"timeout": 0}, {"timeout": float("inf")}, {"workers": True}, {"workers": 1.5}, {"workers": 129}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                WebsiteProbe(**kwargs)
        with patch("typo_monitor.website_probe.requests.Session") as session:
            for url in ("ftp://site.example", "http://user:pass@site.example", "http://site.example#fragment", "http://site.example:bad"):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    WebsiteProbe().probe([url])
            session.assert_not_called()

    def test_loopback_http_503_qualifies_even_when_full_body_is_not_sent(self):
        requests_seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests_seen.append((self.command, self.path))
                self.send_response(503)
                self.send_header("Content-Length", "1000000")
                self.end_headers()
                # Deliberately no body: a client consuming it cannot succeed.

            def log_message(self, *args):
                pass

        try:
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        except PermissionError:
            self.skipTest("This sandbox does not permit loopback sockets")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/"
            row = WebsiteProbe(timeout=1).probe([url])[url]
            self.assertEqual(row["status"], "http_response")
            self.assertEqual(row["http_status"], 503)
            self.assertEqual(requests_seen, [("GET", "/")])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_loopback_tcp_listener_without_http_does_not_qualify(self):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(4096)
                self.request.sendall(b"this is not an HTTP response\r\n")

        try:
            server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        except PermissionError:
            self.skipTest("This sandbox does not permit loopback sockets")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/"
            row = WebsiteProbe(timeout=1).probe([url])[url]
            self.assertEqual(row["status"], "no_http_response")
            self.assertIsNone(row["http_status"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_loopback_redirect_qualifies_without_waiting_for_body_or_following(self):
        release_body, requests_seen = threading.Event(), []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests_seen.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/must-not-follow")
                self.send_header("Content-Length", "1000000")
                self.end_headers()
                self.wfile.flush()
                release_body.wait(timeout=3)

            def log_message(self, *args):
                pass

        try:
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        except PermissionError:
            self.skipTest("This sandbox does not permit loopback sockets")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/redirect"
            row = WebsiteProbe(timeout=1).probe([url])[url]
            self.assertEqual(row["status"], "http_response")
            self.assertEqual(row["http_status"], 302)
            self.assertEqual(requests_seen, ["/redirect"])
            self.assertFalse(release_body.is_set())
        finally:
            release_body.set()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
