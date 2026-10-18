"""Bounded website preflight and one persistent stdin-fed Gowitness process."""

from copy import copy
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import threading
import time

from .adapters import _report_progress, _run_command
from .domains import normalize_domain
from .screenshots import (
    SUPPORTED_VERSION, _JsonlProgress, _row, _validated_preflight,
    _validate_metadata, _apply_preflight,
)
from .website_probe import WebsiteProbe


class _CombinedSignal:
    def __init__(self, external, local):
        self.external, self.local = external, local

    def is_set(self):
        return self.local.is_set() or self.external is not None and self.external.is_set()


class _PreflightFeed:
    """Keep input consumption, network work and completed output bounded."""

    def __init__(self, capture, domains, probe, stopped):
        self.domains, self.probe, self.stopped = domains, probe, stopped
        self.signal = capture.cancel_event
        self.workers, self.probe_timeout = capture.probe_workers, capture.probe_timeout
        self.tasks = queue.Queue(maxsize=self.workers * 2)
        self.output = queue.Queue(maxsize=self.workers * 2)
        self.threads = []

    def check_cancel(self):
        if self.signal is not None and self.signal.is_set():
            raise RuntimeError("Website preflight cancelled; provisional captures were not accepted.")

    def put(self, target, value):
        while not self.stopped.is_set():
            if self.signal is not None and self.signal.is_set():
                return False
            try:
                target.put(value, timeout=0.1)
                return True
            except queue.Full:
                pass
        return False

    def produce(self):
        seen = set()
        try:
            for raw in self.domains:
                if self.stopped.is_set():
                    break
                self.check_cancel()
                domain = normalize_domain(raw)
                if domain in seen:
                    continue
                seen.add(domain)
                if not self.put(self.output, ("domain", domain)):
                    break
                for scheme in ("http", "https"):
                    if not self.put(self.tasks, _row(domain, scheme)["url"]):
                        return
        except BaseException as error:
            self.put(self.output, ("error", error))
        finally:
            for _ in range(self.workers):
                if not self.put(self.tasks, None):
                    break

    def worker(self):
        try:
            while not self.stopped.is_set():
                self.check_cancel()
                try:
                    url = self.tasks.get(timeout=0.1)
                except queue.Empty:
                    continue
                if url is None:
                    break
                # Production probes isolate each HTTP Session. The public
                # probe method remains supported for injected adapters.
                if callable(getattr(self.probe, "_probe_one", None)):
                    diagnostic = self.probe._probe_one(url)
                else:
                    diagnostic = self.probe.probe([url])[url]
                if not self.put(self.output, ("result", (url, diagnostic))):
                    break
        except BaseException as error:
            self.put(self.output, ("error", error))
        finally:
            self.put(self.output, ("finished", None))

    def events(self):
        # A source may be waiting for the next DNS result. The source contract
        # must honor cancellation; daemon threads also cannot hold up shutdown
        # after a producer-side failure while final DNS work is still draining.
        self.threads = [threading.Thread(target=self.worker, name="capture-preflight", daemon=True)
                        for _ in range(self.workers)]
        self.threads.append(threading.Thread(target=self.produce, name="capture-domains", daemon=True))
        for thread in self.threads:
            thread.start()
        finished = 0
        try:
            while finished < self.workers:
                self.check_cancel()
                try:
                    kind, value = self.output.get(timeout=0.25)
                except queue.Empty:
                    yield "tick", None
                    continue
                if kind == "finished":
                    finished += 1
                elif kind == "error":
                    raise value
                else:
                    yield kind, value
        finally:
            self.stopped.set()
            deadline = time.monotonic() + min(self.probe_timeout + 1, 5)
            for thread in self.threads:
                thread.join(timeout=max(0, deadline - time.monotonic()))


def _stop_process(process):
    """Stop the full browser process group, including a blocked stdin reader."""
    def send(sig):
        try:
            if os.name == "posix":
                os.killpg(process.pid, sig)
            elif process.poll() is None:
                process.terminate() if sig == signal.SIGTERM else process.kill()
        except ProcessLookupError:
            pass

    send(signal.SIGTERM)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    finally:
        send(signal.SIGKILL if os.name == "posix" else signal.SIGTERM)
        if process.poll() is None:
            process.kill()
        process.wait()


def capture_stream(capture, domains_iterator, workdir):
    """Preflight endpoints as domains arrive; drain the browser after input EOF.

    The browser's page timeout remains bounded while its producer is open.
    ``capture.timeout`` is the final drain deadline after all DNS/preflight input
    is complete, so waiting for later DNS results cannot spend that deadline.
    """
    capture._check_shutdown()
    results, requested, diagnostics = {}, {}, {}
    callback = getattr(capture, "progress_callback", None)
    process = log = targets = monitor = feed = events = None
    issue = detected_version = None
    preflight_file = None
    paths_ready = False
    stopped = threading.Event()
    capture.stream_stop_event = stopped
    counts = dict.fromkeys(("http_response", "no_http_response", "unknown"), 0)
    last_poll = 0
    launched = 0
    title_filtered = 0
    title_unchanged = 0

    def poll():
        nonlocal last_poll, issue
        capture._check_shutdown()
        if process is not None and process.poll() is not None and issue is None:
            issue = f"Gowitness exited before its input closed (status {process.returncode}); see gowitness.log."
        if monitor is not None and time.monotonic() - last_poll >= 1:
            monitor.metrics.update(eligible=len(requested), launched=launched, title_filtered=title_filtered,
                                   title_unchanged=title_unchanged,
                                   skipped=title_filtered + title_unchanged + sum(counts[key] for key in ("no_http_response", "unknown")), input_open=True)
            monitor.poll()
            last_poll = time.monotonic()

    def start():
        nonlocal process, log, targets, detected_version, monitor, issue
        if not capture.executable:
            issue = "Gowitness is unavailable; install the pinned 3.2.2 binary."
            return
        if not capture.chrome_path or not shutil.which(capture.chrome_path):
            issue = "Chrome/Chromium is unavailable; configure an executable browser path."
            return
        with (workdir / "gowitness.version.txt").open("x", encoding="utf-8") as version_log:
            outcome = _run_command([capture.executable, "version"], cancel_event=capture.cancel_event,
                                   timeout=min(capture.timeout, 10), stdout=version_log,
                                   stderr=subprocess.STDOUT, shell=False, cwd=workdir)
        capture._check_shutdown()
        text = (workdir / "gowitness.version.txt").read_text(encoding="utf-8", errors="replace")
        match = re.search(r"(?im)^\s*gowitness:\s*v?(\d+\.\d+\.\d+)\b", text)
        detected_version = match.group(1) if match else None
        if outcome.returncode or detected_version != SUPPORTED_VERSION:
            issue = "Unsupported Gowitness version; this adapter requires 3.2.2. See gowitness.version.txt."
            return
        screenshot_dir.mkdir(exist_ok=True)
        log = (workdir / "gowitness.log").open("x", encoding="utf-8")
        targets = (workdir / "gowitness-targets.txt").open("x", encoding="utf-8")
        command = [capture.executable, "scan", "file", "-f", "-",
                   "--screenshot-path", str(screenshot_dir), "--screenshot-format", "png",
                   "--write-jsonl", "--write-jsonl-file", str(metadata),
                   "--threads", str(capture.threads), "--timeout", "60",
                   "--chrome-path", capture.chrome_path, "--driver", capture.driver,
                   "--log-scan-errors", "--skip-html", "--skip-network-logs"]
        if getattr(capture, "proxy_url", None):
            command.extend(["--chrome-proxy", capture.proxy_url])
            from .proxy import browser_command
            command[command.index("--chrome-path") + 1] = browser_command(capture.chrome_path, workdir)
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT,
                                   shell=False, cwd=workdir, bufsize=0, start_new_session=os.name == "posix",
                                   env=getattr(capture, "proxy_environment", None))
        os.set_blocking(process.stdin.fileno(), False)
        monitor = _JsonlProgress(metadata, workdir, [], callback, {})
        _report_progress(callback, "screenshots", "Capturing responsive endpoints while DNS checks continue.",
                         current=0, total=len(requested), metrics={"input_open": True})

    def write_url(url):
        nonlocal issue
        if targets is not None:
            targets.write(url + "\n")
            targets.flush()
        if issue is not None or process is None:
            return False
        data = memoryview((url + "\n").encode("ascii"))
        deadline = time.monotonic() + capture.timeout
        try:
            while data:
                poll()
                if issue is not None:
                    return False
                if time.monotonic() >= deadline:
                    issue = "Gowitness stopped consuming its input before the feed deadline; see gowitness.log."
                    _stop_process(process)
                    return False
                try:
                    size = os.write(process.stdin.fileno(), data)
                    data = data[size:]
                except BlockingIOError:
                    time.sleep(0.05)
            monitor.requested.add(url)
            return True
        except (BrokenPipeError, OSError, ValueError) as error:
            issue = f"Gowitness input could not be written: {type(error).__name__}; see gowitness.log."
            return False

    try:
        workdir = Path(workdir).absolute()
        if workdir.is_symlink() or not workdir.is_dir():
            raise ValueError("Screenshot work directory must be an existing directory, not a symlink.")
        workdir = workdir.resolve(strict=True)
        screenshot_dir = workdir / "screenshots"
        if screenshot_dir.is_symlink() or (screenshot_dir.exists() and any(screenshot_dir.iterdir())):
            raise ValueError("Screenshot output directory must be empty and must not be a symlink.")
        metadata, preflight_file = workdir / "gowitness.jsonl", workdir / "preflight.json"
        for path in (metadata, preflight_file, workdir / "gowitness.version.txt",
                     workdir / "gowitness.log", workdir / "gowitness-targets.txt"):
            if path.exists() or path.is_symlink():
                raise ValueError("Existing screenshot metadata cannot be reused for a new capture.")
        paths_ready = True
        # Isolate cancellation attributes even for an injected reusable probe.
        # An OS resolver call can outlive requests' HTTP deadline; its old
        # worker must retain this run's stopped signal when a later scan starts.
        probe = copy(capture.probe) if capture.probe is not None else WebsiteProbe(
            timeout=capture.probe_timeout, workers=capture.probe_workers)
        probe.cancel_event = _CombinedSignal(capture.cancel_event, stopped)
        probe.run_id = getattr(capture, "run_id", "manual")
        probe.proxy_url = getattr(capture, "proxy_url", None)
        probe.collect_titles = bool(getattr(capture, "collect_titles", False) or getattr(capture, "title_filter", {}).get("enabled"))
        feed = _PreflightFeed(capture, domains_iterator, probe, stopped)
        events = feed.events()
        for kind, value in events:
            poll()
            if kind == "domain":
                results[value] = [_row(value, scheme) for scheme in ("http", "https")]
                continue
            if kind == "tick":
                continue
            url, diagnostic = value
            diagnostic = _validated_preflight({url: diagnostic}, {url})[url]
            diagnostics[url] = diagnostic
            counts[diagnostic["status"]] += 1
            # Only the coordinator mutates accepted row/metadata bookkeeping.
            domain = url.split("://", 1)[1].rsplit(":", 1)[0]
            scheme = url.split(":", 1)[0]
            row = next(row for row in results[domain] if row["scheme"] == scheme)
            eligible = _apply_preflight(capture, row, diagnostic, domain)
            title_filtered += diagnostic.get("skip_reason") == "title_rule"
            title_unchanged += diagnostic.get("skip_reason") == "unchanged_title"
            _report_progress(callback, "websites", current=len(diagnostics), total=len(results) * 2,
                             metrics={"response": counts["http_response"],
                                      "no_response": counts["no_http_response"],
                                      "uncertain": counts["unknown"], "input_open": True})
            if not eligible:
                _report_progress(callback, "screenshots", metrics={"eligible": len(requested), "launched": launched,
                    "title_filtered": title_filtered,
                    "title_unchanged": title_unchanged,
                    "skipped": title_filtered + title_unchanged + counts["no_http_response"] + counts["unknown"]})
                continue
            requested[url] = row
            if process is None and issue is None:
                try:
                    start()
                except (OSError, subprocess.TimeoutExpired) as error:
                    issue = f"Gowitness could not start: {type(error).__name__}; see gowitness.version.txt or gowitness.log."
            if write_url(url):
                row["capture_queued"] = True
                launched += 1
            else:
                row.update(status="unavailable", error=issue or "Gowitness input is unavailable.")
        capture._check_shutdown()
        with preflight_file.open("x", encoding="utf-8") as stream:
            json.dump(diagnostics, stream, indent=2)
        _report_progress(callback, "websites", current=len(diagnostics), total=len(results) * 2,
                         metrics={"response": counts["http_response"], "no_response": counts["no_http_response"],
                                  "uncertain": counts["unknown"], "input_open": False})
        if process is not None:
            try:
                process.stdin.close()
            except (OSError, ValueError):
                pass
            deadline = time.monotonic() + capture.timeout
            while process.poll() is None:
                capture._check_shutdown()
                if monitor is not None:
                    monitor.metrics["input_open"] = False
                    monitor.poll()
                if time.monotonic() >= deadline:
                    issue = "Gowitness drain deadline exceeded after its input completed; finished artifacts were retained."
                    _stop_process(process)
                    break
                try:
                    process.wait(timeout=0.25)
                except subprocess.TimeoutExpired:
                    pass
            if process.returncode and issue is None:
                issue = capture.exit_issue(workdir, process.returncode)
            elif process.returncode:
                issue = (issue or "") + " " + capture.exit_issue(workdir, process.returncode)
            if monitor is not None:
                monitor.metrics["input_open"] = False
                monitor.poll()
        queued = {url: row for url, row in requested.items() if row.get("capture_queued")}
        malformed, foreign, duplicates = _validate_metadata(metadata, workdir, queued, capture._check_shutdown)
        detail = (f"Captured {sum(row['status'] == 'captured' for row in requested.values())} of "
                  f"{len(requested)} HTTP-responsive endpoints using one streamed Gowitness process.")
        if issue:
            detail += " " + issue
        if malformed or foreign or duplicates:
            detail += f" Ignored metadata: {malformed} malformed, {foreign} unrequested, {len(duplicates)} duplicate URLs."
        if results and not requested:
            detail = "No endpoints qualified for browser capture after website and title checks; see preflight.json. All names are checked again next run."
        stage = capture._stage(results, detail, issue=bool(issue or malformed or foreign or duplicates),
                               version=detected_version)
        if not results:
            stage.update(status="skipped", detail="No currently resolving candidates to capture.")
        _report_progress(callback, "screenshots", current=len(requested), total=len(requested), metrics=stage)
        return results, stage
    except (OSError, ValueError) as error:
        detail = f"Streamed screenshot capture could not complete: {type(error).__name__}: {error}"
        for rows in results.values():
            for row in rows:
                if row["status"] != "skipped":
                    row.update(status="failed", relative_path=None, error=detail)
        return results, capture._stage(results, detail, failed=True, version=detected_version)
    finally:
        stopped.set()
        if process is not None:
            if process.poll() is None or process.returncode != 0:
                _stop_process(process)
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except (OSError, ValueError):
                    pass
        if events is not None:
            events.close()
        for stream in (targets, log):
            if stream is not None:
                stream.close()
        if paths_ready and not preflight_file.exists() and not preflight_file.is_symlink():
            try:
                with preflight_file.open("x", encoding="utf-8") as stream:
                    json.dump(diagnostics, stream, indent=2)
            except OSError:
                # Capture diagnostics cannot hide a cancellation or original
                # artifact error during cleanup.
                pass
