"""HTTP preflight with optional bounded title/text extraction; transport errors are not DNS facts."""

from contextlib import closing
from datetime import datetime, timezone
import math
import logging
import socket
import time
from urllib.parse import urlsplit

import requests
from urllib3.util import Timeout
from urllib3.exceptions import NameResolutionError

from .concurrency import bounded_map
from .adapters import _report_progress

LOG = logging.getLogger(__name__)
# Match the pinned Gowitness browser request identity so the preliminary title
# check is less likely to receive a different page solely because of its UA.
BROWSER_USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")


def _name_resolution_error(error):
    pending, visited = [error], set()
    while pending:
        current = pending.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        if isinstance(current, (socket.gaierror, NameResolutionError)):
            return True
        pending.extend(value for value in (getattr(current, "reason", None), current.__cause__, current.__context__, *current.args)
                       if isinstance(value, BaseException))
    return False


class WebsiteProbe:
    def __init__(self, timeout=3, workers=24):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Website probe timeout must be positive and finite.")
        if not isinstance(workers, int) or isinstance(workers, bool) or not 1 <= workers <= 128:
            raise ValueError("Website probe workers must be between 1 and 128.")
        self.timeout, self.workers = timeout, workers
        self.cancel_event = None

    def _check_cancel(self):
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise RuntimeError("Website preflight cancelled; incomplete work was not accepted.")

    def _probe_one(self, url):
        self._check_cancel()
        deadline = time.monotonic() + self.timeout
        tls_error = None
        tls_verified = None

        def result(status, error=None, code=None):
            return {"url": url, "status": status, "http_status": code,
                    "error": error, "tls_error": tls_error, "tls_verified": tls_verified,
                    "checked_at": datetime.now(timezone.utc).isoformat()}

        # Only an explicit run proxy is used; no environment/.netrc settings
        # and no Session shared by threads.
        with requests.Session() as session:
            session.trust_env = False
            proxy_url = getattr(self, "proxy_url", None)
            if proxy_url:
                session.proxies = {"http": proxy_url, "https": proxy_url}
            session.headers["User-Agent"] = BROWSER_USER_AGENT
            collect_text = bool(getattr(self, "collect_text", False))
            collect_titles = bool(getattr(self, "collect_titles", False) or collect_text)
            if collect_titles:
                session.headers["Accept-Encoding"] = "identity"
            # Requests otherwise consumes redirect bodies while preparing
            # Response.next, even with allow_redirects=False and stream=True.
            session.resolve_redirects = lambda *args, **kwargs: iter(())
            for verify in (True, False):
                self._check_cancel()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return result("unknown", "Website check uncertain: its timeout budget expired.")
                try:
                    with session.get(url, stream=True, allow_redirects=False, verify=verify,
                                     timeout=Timeout(total=remaining, connect=remaining, read=remaining)) as response:
                        self._check_cancel()
                        code = response.status_code
                        if not isinstance(code, int) or isinstance(code, bool) or not 100 <= code <= 599:
                            return result("unknown", "Website check uncertain: invalid response status.")
                        tls_verified = verify if url.startswith("https:") else None
                        diagnostic = result("http_response", code=code)
                        if collect_titles:
                            from .title_filter import inspect_title
                            diagnostic.update(inspect_title(response, session, deadline, self._check_cancel, collect_text=collect_text))
                        return diagnostic
                except requests.exceptions.SSLError as error:
                    tls_error = f"TLS verification/handshake failed: {type(error).__name__}."
                    if verify:
                        # A broken certificate does not mean there is no website.
                        # The fallback still requires an actual HTTP response.
                        continue
                    return result("unknown", "Website check uncertain: TLS failed even without certificate verification.")
                except requests.exceptions.Timeout as error:
                    return result("unknown", f"Website check uncertain: {type(error).__name__}.")
                except requests.exceptions.ConnectionError as error:
                    if proxy_url:
                        return result("unknown", "Website check uncertain: connection through the configured proxy failed.")
                    if tls_error or _name_resolution_error(error):
                        return result("unknown", "Website check uncertain: connection failed during TLS fallback or name resolution.")
                    return result("no_http_response", f"No HTTP response: {type(error).__name__}.")
                except requests.exceptions.RequestException as error:
                    return result("unknown", f"Website check uncertain: {type(error).__name__}.")

    def probe(self, urls):
        self._check_cancel()
        requested = list(dict.fromkeys(urls))
        for url in requested:
            if not isinstance(url, str):
                raise ValueError("Website probe URLs must be strings.")
            parsed = urlsplit(url)
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                    or parsed.username is not None or parsed.password is not None
                    or parsed.fragment or (parsed.port is not None and not 1 <= parsed.port <= 65535)):
                raise ValueError("Website probes require explicit HTTP/HTTPS URLs without credentials or fragments.")
        results = {}
        counts = dict.fromkeys(("http_response", "no_http_response", "unknown"), 0)
        callback = getattr(self, "progress_callback", None)

        def progress():
            _report_progress(callback, "websites", current=len(results), total=len(requested),
                             metrics={"response": counts["http_response"], "no_response": counts["no_http_response"],
                                      "uncertain": counts["unknown"]})

        progress()
        last_report = time.monotonic()
        with closing(bounded_map(self._probe_one, requested, workers=self.workers,
                                 check_cancel=self._check_cancel, thread_name_prefix="website")) as completed:
            for url, diagnostic in completed:
                results[url] = diagnostic
                counts[diagnostic["status"]] += 1
                progress()
                if time.monotonic() - last_report >= 5 or len(results) == len(requested):
                    LOG.info("Run %s: website preflight %d/%d checked; %d HTTP responses, %d no HTTP response, %d uncertain",
                             getattr(self, "run_id", "manual"), len(results), len(requested), counts["http_response"],
                             counts["no_http_response"], counts["unknown"])
                    last_report = time.monotonic()
        self._check_cancel()
        return results
