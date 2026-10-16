"""Overlap provisional DNS positives with bounded website/browser work."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import logging
import queue
import threading


LOG = logging.getLogger(__name__)
_END = object()


class _CaptureSignal:
    def __init__(self, external, local):
        self.external, self.local = external, local

    def is_set(self):
        return self.local.is_set() or self.external.is_set()

    def wait(self, timeout=None):
        import time
        deadline = None if timeout is None else time.monotonic() + timeout
        while not self.is_set():
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                return False
            self.local.wait(.05 if remaining is None else min(.05, remaining))
        return True


def _failed_rows(domain, detail):
    return [{"scheme": scheme, "url": f"{scheme}://{domain}:{port}",
             "status": "failed", "relative_path": None, "title": None,
             "http_status": None, "error": detail,
             "captured_at": datetime.now(timezone.utc).isoformat()}
            for scheme, port in (("http", 80), ("https", 443))]


class CaptureOverlap:
    """Never block the DNS reader; deferred positives are fed after DNS ends.

    Only the scan thread calls offer()/finish(). The capture thread owns the
    iterator and browser lifecycle. Neither thread publishes accepted evidence.
    """

    def __init__(self, resolver, capturer, candidates, workdir, signal, report):
        self.resolver, self.capturer = resolver, capturer
        self.workdir, self.signal, self.report = workdir, signal, report
        self.queue = queue.Queue(maxsize=256)
        self.submitted = set()
        self.abort, self.done = threading.Event(), threading.Event()
        self.lock = threading.RLock()
        self.metrics = {"dns_checked": 0, "dns_total": len(candidates),
                        "resolved": 0, "negative": 0, "uncertain": 0,
                        "web_checked": 0, "web_total": 0, "captures_reported": 0}
        self.final_resolving = None
        self.saved = (getattr(resolver, "result_callback", None),
                      getattr(resolver, "progress_callback", None),
                      getattr(capturer, "progress_callback", None),
                      getattr(capturer, "cancel_event", None))
        self.pool = None
        try:
            self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="capture-pipeline")
            resolver.result_callback = self.offer
            resolver.progress_callback = self.progress
            capturer.progress_callback = self.progress
            capturer.cancel_event = _CaptureSignal(signal, self.abort)
            self.future = self.pool.submit(self._capture)
        except BaseException:
            self.abort.set()
            if self.pool is not None:
                self.pool.shutdown(wait=True, cancel_futures=True)
            self._restore()
            raise

    def _check_cancel(self):
        if self.signal.is_set():
            raise RuntimeError("Scan stopped; provisional captures were not accepted.")

    def _capture(self):
        try:
            return self.capturer.capture_stream(self._domains(), self.workdir)
        finally:
            self.done.set()

    def _domains(self):
        while True:
            self._check_cancel()
            stream_stop = getattr(self.capturer, "stream_stop_event", None)
            if self.abort.is_set() or stream_stop is not None and stream_stop.is_set():
                return
            try:
                domain = self.queue.get(timeout=.2)
            except queue.Empty:
                continue
            if domain is _END:
                return
            if self.final_resolving is not None and domain not in self.final_resolving:
                continue
            yield domain

    def offer(self, domain, observation):
        """Called for provisional triples; a full queue means defer, never drop."""
        if observation.get("status") != "resolved" or domain in self.submitted or self.done.is_set():
            return
        self._check_cancel()
        try:
            self.queue.put_nowait(domain)
        except queue.Full:
            return
        self.submitted.add(domain)

    def progress(self, stage, message=None, *, current=None, total=None, metrics=None, level="info"):
        with self.lock:
            values = metrics or {}
            if stage == "dns":
                if current is not None:
                    self.metrics["dns_checked"] = current
                for key in ("resolved", "negative", "uncertain", "queries_completed", "queries_total", "concurrency"):
                    if key in values:
                        self.metrics[key] = values[key]
            elif stage == "websites":
                if current is not None:
                    self.metrics["web_checked"] = current
                if total is not None:
                    self.metrics["web_total"] = max(self.metrics["web_total"], total)
            elif stage == "screenshots":
                if "reported" in values:
                    self.metrics["captures_reported"] = values["reported"]
                for key in ("eligible", "launched", "skipped"):
                    if key in values:
                        self.metrics[key] = values[key]
            self.report("pipeline", f"{stage}: {message}" if message else None,
                        current=self.metrics["dns_checked"], total=self.metrics["dns_total"],
                        metrics=dict(self.metrics), level=level)

    def _put(self, value):
        while not self.done.is_set():
            self._check_cancel()
            try:
                self.queue.put(value, timeout=.2)
                return True
            except queue.Full:
                pass
        return False

    def finish(self, observations):
        """Drain final positives, then discard any invalidated early captures."""
        resolving = {domain for domain, item in observations.items() if item["status"] == "resolved"}
        with self.lock:
            self.final_resolving = resolving
            self.metrics["dns_checked"] = len(observations)
            self.metrics["resolved"] = len(resolving)
            self.metrics["web_total"] = max(self.metrics["web_total"], len(resolving) * 2)
            self.progress("dns", "DNS checks finished; finishing HTTP checks and browser captures.")
        for domain in sorted(resolving - self.submitted):
            if not self._put(domain):
                break
            self.submitted.add(domain)
        self._put(_END)
        try:
            results, stage = self.future.result()
        except Exception as exc:
            self._check_cancel()
            LOG.exception("Streaming screenshot stage failed; retaining final DNS evidence")
            results = {}
            stage = {"status": "failed", "detail": f"{type(exc).__name__}: {exc}"}
        self._check_cancel()
        discarded = len(set(results) - resolving)
        results = {domain: rows for domain, rows in results.items() if domain in resolving}
        missing = resolving - set(results)
        for domain in missing:
            results[domain] = _failed_rows(domain, "Capture pipeline ended before checking this domain; see source diagnostics.")
        stage = dict(stage)
        rows = [row for domain_rows in results.values() for row in domain_rows]
        stage.update(overlapped_dns=True, discarded_provisional_domains=discarded,
                     attempts=len(rows), captured=sum(row["status"] == "captured" for row in rows),
                     failed=sum(row["status"] == "failed" for row in rows),
                     unavailable=sum(row["status"] == "unavailable" for row in rows),
                     skipped=sum(row["status"] == "skipped" for row in rows),
                     eligible=sum(row.get("preflight", {}).get("status") == "http_response" for row in rows),
                     launched=sum(bool(row.get("capture_queued")) for row in rows))
        for status in ("http_response", "no_http_response", "unknown"):
            stage["preflight_" + status] = sum(row.get("preflight", {}).get("status") == status for row in rows)
        if missing:
            stage["status"] = "failed" if stage.get("status") == "failed" else "partial"
            stage["detail"] = stage.get("detail", "") + f" {len(missing)} final resolving domains did not complete capture checks."
        if discarded:
            stage["detail"] = stage.get("detail", "") + f" Discarded captures for {discarded} domains whose final DNS result was uncertain."
        return results, stage

    def close(self):
        # Also runs when DNS fails before EOF. The iterator wakes within 200ms,
        # capture workers see the local stop, and the browser process is drained
        # before shared adapter state can be reused by the next scan.
        self.abort.set()
        try:
            self.pool.shutdown(wait=True)
        finally:
            self._restore()

    def _restore(self):
        (self.resolver.result_callback, self.resolver.progress_callback,
         self.capturer.progress_callback, self.capturer.cancel_event) = self.saved
