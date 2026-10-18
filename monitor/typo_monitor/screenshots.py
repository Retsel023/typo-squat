"""Gowitness 3.2.2 capture with explicit attempts and verified local artifacts."""

from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

from .adapters import _report_progress, _run_command
from .domains import normalize_domain
from .website_probe import WebsiteProbe
from .title_filter import MAX_TITLE_CHARS, TITLE_STATUSES, matching_rule, rule_scope


SUPPORTED_VERSION = "3.2.2"


def _now():
    return datetime.now(timezone.utc).isoformat()


def _executable_path(value):
    value = str(value)
    found = shutil.which(value)
    if found:
        return str(Path(found).absolute())
    # Capture executes in the run directory; preserve caller-relative tool paths.
    if "/" in value or "\\" in value:
        return str(Path(value).absolute())
    return value


def _row(domain, scheme):
    port = 80 if scheme == "http" else 443
    return {"scheme": scheme, "url": f"{scheme}://{domain}:{port}",
            "status": "failed", "relative_path": None, "title": None,
            "http_status": None, "error": "No JSONL result was produced for this requested URL; see gowitness.log.",
            "captured_at": _now()}


def _validated_preflight(diagnostics, requested):
    if not isinstance(diagnostics, dict) or set(diagnostics) != set(requested):
        raise ValueError("Website preflight must return exactly one result for every requested URL.")
    validated = {}
    for url, entry in diagnostics.items():
        if (not isinstance(entry, dict) or entry.get("url") != url
                or entry.get("status") not in {"http_response", "no_http_response", "unknown"}):
            raise ValueError("Website preflight returned malformed URL/status metadata.")
        code, error = entry.get("http_status"), entry.get("error")
        if entry["status"] == "http_response":
            if not isinstance(code, int) or isinstance(code, bool) or not 100 <= code <= 599:
                raise ValueError("Responsive website preflight requires an HTTP status code.")
        elif code is not None or not isinstance(error, str) or not error:
            raise ValueError("Skipped website preflight requires an explicit diagnostic and no HTTP status.")
        if (error is not None and not isinstance(error, str)
                or entry.get("tls_error") is not None and not isinstance(entry["tls_error"], str)
                or entry.get("tls_verified") is not None and not isinstance(entry["tls_verified"], bool)):
            raise ValueError("Website preflight returned invalid diagnostic fields.")
        try:
            checked = datetime.fromisoformat(entry["checked_at"].replace("Z", "+00:00"))
            if checked.utcoffset() is None:
                raise ValueError
        except (KeyError, AttributeError, TypeError, ValueError) as exc:
            raise ValueError("Website preflight requires an aware check timestamp.") from exc
        validated[url] = {"url": url, "status": entry["status"], "http_status": code,
                          "error": error, "tls_error": entry.get("tls_error"),
                          "tls_verified": entry.get("tls_verified"),
                          "checked_at": checked.astimezone(timezone.utc).isoformat()}
        title = entry.get("title")
        title_status = entry.get("title_status", "disabled")
        title_url = entry.get("title_url")
        title_code, title_bytes = entry.get("title_http_status"), entry.get("title_bytes", 0)
        if (title is not None and (not isinstance(title, str) or len(title) > MAX_TITLE_CHARS)
                or not isinstance(title_status, str) or title_status not in TITLE_STATUSES
                or title_status == "found" and not title
                or title_url is not None and (not isinstance(title_url, str) or len(title_url) > 2048)
                or title_code is not None and (type(title_code) is not int or not 100 <= title_code <= 599)
                or type(title_bytes) is not int or not 0 <= title_bytes <= 64 * 1024):
            raise ValueError("Website preflight returned invalid title metadata.")
        validated[url].update(title=title, title_status=title_status, title_url=title_url,
                              title_http_status=title_code, title_bytes=title_bytes)
    return validated


def _apply_preflight(capture, row, diagnostic, domain):
    """Return whether a responsive endpoint should enter the browser queue."""
    row.update(preflight=diagnostic, title=diagnostic.get("title"), http_status=diagnostic.get("http_status"))
    from .capture_changes import compare
    unchanged = compare(capture, domain, row, diagnostic)
    if diagnostic["status"] != "http_response":
        prefix = "Website check uncertain: " if diagnostic["status"] == "unknown" else "No HTTP response: "
        error = diagnostic["error"]
        row.update(status="skipped", error=error if error.startswith(prefix) else prefix + error,
                   captured_at=diagnostic["checked_at"])
        return False
    rule = matching_rule(diagnostic, getattr(capture, "title_filter", {}),
                         original=domain in getattr(capture, "original_domains", set()))
    if rule:
        scope = rule_scope(rule, getattr(capture, "title_filter", {}))
        diagnostic.update(skip_reason="title_rule", matched_rule=rule, rule_scope=scope)
        row.update(status="skipped", error=f"Screenshot excluded by title rule: {rule} ({scope})",
                   captured_at=diagnostic["checked_at"])
        return False
    if unchanged:
        row.update(status="skipped", error="Title unchanged; no new screenshot requested.",
                   captured_at=diagnostic["checked_at"])
        return False
    return True


def _image_path(workdir, filename):
    """Accept only metadata-named PNG/JPEG files directly in screenshots/."""
    if (not isinstance(filename, str) or not filename or filename in {".", ".."}
            or "/" in filename or "\\" in filename or "\x00" in filename):
        raise ValueError("Screenshot metadata does not contain a safe basename.")
    path = workdir / "screenshots" / filename
    if path.parent.is_symlink() or path.is_symlink():
        raise ValueError("Screenshot symlinks are not accepted.")
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(workdir) or not resolved.is_file():
        raise ValueError("Screenshot artifact escapes the run directory or is not a regular file.")
    with resolved.open("rb") as stream:
        header = stream.read(33)
        stream.seek(-2, os.SEEK_END)
        footer = stream.read(2)
    suffix = resolved.suffix.lower()
    if header.startswith(b"\x89PNG\r\n\x1a\n") and header[12:16] == b"IHDR" and len(header) == 33:
        if suffix != ".png":
            raise ValueError("PNG screenshot has an incompatible filename extension.")
    elif header.startswith(b"\xff\xd8\xff") and footer == b"\xff\xd9":
        if suffix not in {".jpg", ".jpeg"}:
            raise ValueError("JPEG screenshot has an incompatible filename extension.")
    else:
        raise ValueError("Screenshot artifact is not a recognized PNG or JPEG image.")
    return resolved.relative_to(workdir).as_posix()


def _validate_metadata(metadata, workdir, requested, check_shutdown):
    """Select only requested, unique results with safe verified image artifacts."""
    malformed, foreign, duplicates = 0, 0, set()
    records = {}
    if metadata.exists():
        if metadata.is_symlink() or not metadata.resolve().is_relative_to(workdir):
            raise ValueError("Gowitness metadata is not a safe local file.")
        with metadata.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                check_shutdown()
                try:
                    record = json.loads(line)
                except (ValueError, TypeError):
                    malformed += 1
                    continue
                if not isinstance(record, dict) or not isinstance(record.get("url"), str):
                    malformed += 1
                    continue
                url = record["url"]
                if url not in requested:
                    foreign += 1
                    continue
                if url in records:
                    duplicates.add(url)
                records[url] = record
    artifact_urls = {}
    for url, record in records.items():
        filename = record.get("file_name")
        if isinstance(filename, str) and filename:
            artifact_urls.setdefault(filename, set()).add(url)
    for url, record in records.items():
        row = requested[url]
        if url in duplicates:
            row["error"] = "Duplicate JSONL results for this requested URL; no artifact selected."
            continue
        filename = record.get("file_name")
        if isinstance(filename, str) and len(artifact_urls.get(filename, ())) > 1:
            row["error"] = "Multiple requested URLs share one screenshot artifact; no artifact selected."
            continue
        row["title"] = record.get("title") if isinstance(record.get("title"), str) else None
        code = record.get("response_code")
        row["http_status"] = code if isinstance(code, int) and not isinstance(code, bool) and 100 <= code <= 599 else None
        try:
            timestamp = datetime.fromisoformat(str(record.get("probed_at", "")).replace("Z", "+00:00"))
            if timestamp.utcoffset() is not None:
                row["captured_at"] = timestamp.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass
        if record.get("failed") is not False or record.get("is_pdf") is not False:
            row["error"] = str(record.get("failed_reason") or "Gowitness marked the capture failed or returned unsupported screenshot metadata.")
            continue
        if row["http_status"] is None:
            row["error"] = "Gowitness metadata has no valid HTTP response code."
            continue
        try:
            relative_path = _image_path(workdir, record.get("file_name"))
        except (OSError, ValueError) as error:
            row["error"] = f"Screenshot artifact rejected: {error}"
            continue
        row.update(status="captured", relative_path=relative_path, error=None)
    return malformed, foreign, duplicates


class _JsonlProgress:
    """Read bounded, complete records for telemetry; final validation stays separate."""

    _MAX_LINE = 1024 * 1024
    _MAX_TICK_BYTES = 4 * 1024 * 1024

    def __init__(self, path, workdir, requested, callback, metrics):
        self.path, self.workdir = path, workdir
        self.requested, self.callback = set(requested), callback
        self.metrics = dict(metrics)
        self.offset, self.identity = 0, None
        self.pending = bytearray()
        self.discarding = False
        self.seen, self.failed = set(), set()

    def _record(self, line):
        try:
            record = json.loads(line)
        except (UnicodeError, ValueError, TypeError, RecursionError):
            return
        if not isinstance(record, dict) or not isinstance(record.get("url"), str):
            return
        url = record["url"]
        if url not in self.requested:
            return
        self.seen.add(url)
        if record.get("failed") is True:
            self.failed.add(url)

    def _consume(self, chunk):
        pieces = chunk.split(b"\n")
        for index, piece in enumerate(pieces):
            complete = index < len(pieces) - 1
            if not self.discarding:
                if len(self.pending) + len(piece) > self._MAX_LINE:
                    self.pending.clear()
                    self.discarding = True
                else:
                    self.pending.extend(piece)
            if complete:
                if not self.discarding and self.pending:
                    self._record(self.pending)
                self.pending.clear()
                self.discarding = False

    def poll(self):
        try:
            if self.path.is_symlink() or not self.path.resolve().is_relative_to(self.workdir):
                return
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            descriptor = os.open(self.path, flags)
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    return
                identity = (info.st_dev, info.st_ino)
                if identity != self.identity or info.st_size < self.offset:
                    self.offset, self.identity = 0, identity
                    self.pending.clear()
                    self.discarding = False
                stream.seek(self.offset)
                remaining = self._MAX_TICK_BYTES
                while remaining > 0:
                    chunk = stream.read(min(64 * 1024, remaining))
                    if not chunk:
                        break
                    self.offset += len(chunk)
                    remaining -= len(chunk)
                    self._consume(chunk)
        except (OSError, ValueError):
            return
        _report_progress(self.callback, "screenshots", current=len(self.seen), total=len(self.requested),
                         metrics={**self.metrics, "reported": len(self.seen),
                                  "reported_failed": len(self.failed), "metadata_bytes": self.offset})


class GowitnessCapture:
    """Capture HTTP and HTTPS independently without modifying DNS observations.

    A supported Gowitness binary and an explicit or installed Chrome/Chromium
    binary are required. Browser downloads and filename inference are avoided.
    """

    def __init__(self, executable=None, chrome_path=None, timeout=900, threads=4, driver="gorod",
                 probe=None, probe_timeout=3, probe_workers=24):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Screenshot timeout must be positive and finite.")
        if not isinstance(threads, int) or isinstance(threads, bool) or not 1 <= threads <= 32:
            raise ValueError("Screenshot threads must be between 1 and 32.")
        self.executable = _executable_path(executable) if executable else shutil.which("gowitness")
        self.chrome_path = _executable_path(chrome_path) if chrome_path else None
        if not self.chrome_path:
            for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "google-chrome-unstable"):
                self.chrome_path = shutil.which(name)
                if self.chrome_path:
                    break
        if not self.chrome_path:
            candidate = Path("/opt/google/chrome-unstable/chrome")
            if candidate.is_file() and os.access(candidate, os.X_OK):
                self.chrome_path = str(candidate)
        self.timeout, self.threads = timeout, threads
        if driver not in {"gorod", "chromedp"}:
            raise ValueError("Capture driver must be gorod or chromedp.")
        self.driver = driver
        # Validate even when a fixture probe is injected; no network runs here.
        WebsiteProbe(timeout=probe_timeout, workers=probe_workers)
        self.probe = probe
        self.probe_timeout, self.probe_workers = probe_timeout, probe_workers
        self.cancel_event = None

    def _check_shutdown(self):
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise RuntimeError("Screenshot capture canceled during shutdown.")

    @staticmethod
    def _stage(results, detail, *, failed=False, issue=False, version=None):
        rows = [row for domain_rows in results.values() for row in domain_rows]
        captured = sum(row["status"] == "captured" for row in rows)
        unsuccessful = any(row["status"] in {"failed", "unavailable"} for row in rows)
        counts = {status: sum(row.get("preflight", {}).get("status") == status for row in rows)
                  for status in ("http_response", "no_http_response", "unknown")}
        title_filtered = sum(row.get("preflight", {}).get("skip_reason") == "title_rule" for row in rows)
        title_unchanged = sum(row.get("preflight", {}).get("skip_reason") == "unchanged_title" for row in rows)
        if title_filtered:
            detail += f" {title_filtered} endpoints excluded by configured title phrases; DNS inventory was retained."
        if title_unchanged:
            detail += f" {title_unchanged} endpoints had unchanged titles and did not request screenshots."
        return {"status": "failed" if failed else "partial" if issue or unsuccessful or counts["unknown"] else "ok",
                "detail": detail, "version": version, "required_version": SUPPORTED_VERSION,
                "attempts": len(rows), "captured": captured,
                "failed": sum(row["status"] == "failed" for row in rows),
                "unavailable": sum(row["status"] == "unavailable" for row in rows),
                "eligible": counts["http_response"] - title_filtered - title_unchanged,
                "title_filtered": title_filtered,
                "title_unchanged": title_unchanged,
                "titles_found": sum(row.get("preflight", {}).get("title_status") == "found" for row in rows),
                "launched": sum(row.get("capture_queued", False) for row in rows),
                "skipped": sum(row["status"] == "skipped" for row in rows),
                **{"preflight_" + status: count for status, count in counts.items()}}

    def capture(self, candidates, workdir):
        self._check_shutdown()
        domains = sorted({normalize_domain(domain) for domain in candidates})
        results = {domain: [_row(domain, scheme) for scheme in ("http", "https")] for domain in domains}
        requested = {row["url"]: row for rows in results.values() for row in rows}
        detected_version = None
        callback = getattr(self, "progress_callback", None)
        if not requested:
            stage = self._stage(results, "No currently resolving candidates to capture.")
            return results, {**stage, "status": "skipped"}

        def unavailable(detail):
            for row in requested.values():
                row.update(status="unavailable", error=detail)
            stage = self._stage(results, detail, failed=True, version=detected_version)
            _report_progress(callback, "screenshots", current=len(requested), total=len(requested), metrics=stage)
            return results, stage

        workdir = Path(workdir).absolute()
        try:
            if workdir.is_symlink() or not workdir.is_dir():
                raise ValueError("Screenshot work directory must be an existing directory, not a symlink.")
            workdir = workdir.resolve(strict=True)
            screenshot_dir = workdir / "screenshots"
            if screenshot_dir.is_symlink() or (screenshot_dir.exists() and any(screenshot_dir.iterdir())):
                raise ValueError("Screenshot output directory must be empty and must not be a symlink.")
            metadata = workdir / "gowitness.jsonl"
            if metadata.exists() or metadata.is_symlink():
                raise ValueError("Existing Gowitness metadata cannot be reused for a new capture.")
            preflight_file = workdir / "preflight.json"
            if preflight_file.exists() or preflight_file.is_symlink():
                raise ValueError("Existing website preflight cannot be reused for a new capture.")
            probe = self.probe or WebsiteProbe(timeout=self.probe_timeout, workers=self.probe_workers)
            probe.cancel_event = self.cancel_event
            probe.run_id = getattr(self, "run_id", "manual")
            probe.progress_callback = callback
            probe.proxy_url = getattr(self, "proxy_url", None)
            probe.collect_titles = bool(getattr(self, "collect_titles", False) or getattr(self, "title_filter", {}).get("enabled"))
            diagnostics = probe.probe(list(requested))
            self._check_shutdown()
            try:
                diagnostics = _validated_preflight(diagnostics, requested)
            except ValueError as error:
                with preflight_file.open("x", encoding="utf-8") as stream:
                    json.dump({"error": str(error), "checked_at": _now()}, stream, indent=2)
                raise
            for url, diagnostic in diagnostics.items():
                row = requested[url]
                _apply_preflight(self, row, diagnostic, url.split("://", 1)[1].rsplit(":", 1)[0])
            with preflight_file.open("x", encoding="utf-8") as stream:
                json.dump(diagnostics, stream, indent=2)
            requested = {url: row for url, row in requested.items() if row["preflight"]["status"] == "http_response"
                         and row["preflight"].get("skip_reason") not in {"title_rule", "unchanged_title"}}
            progress_metrics = {"eligible": len(requested), "launched": 0,
                                "title_filtered": sum(row.get("preflight", {}).get("skip_reason") == "title_rule" for rows in results.values() for row in rows),
                                "title_unchanged": sum(row.get("preflight", {}).get("skip_reason") == "unchanged_title" for rows in results.values() for row in rows),
                                "skipped": sum(row["status"] == "skipped" for rows in results.values() for row in rows)}
            _report_progress(callback, "screenshots", current=0, total=len(requested), metrics=progress_metrics)
            if not requested:
                return results, self._stage(results, "No endpoints qualified for browser capture after website and title checks; see preflight.json. All names are checked again next run.")
            if not self.executable:
                return unavailable("Gowitness is unavailable; install the pinned 3.2.2 binary.")
            if not self.chrome_path or not shutil.which(self.chrome_path):
                return unavailable("Chrome/Chromium is unavailable; configure an executable browser path.")
            screenshot_dir.mkdir(exist_ok=True)
            with (workdir / "gowitness.version.txt").open("x", encoding="utf-8") as version_log:
                version_result = _run_command(
                    [self.executable, "version"], cancel_event=self.cancel_event,
                    timeout=min(self.timeout, 10), stdout=version_log,
                    stderr=subprocess.STDOUT, shell=False, cwd=workdir,
                )
            self._check_shutdown()
            version_text = (workdir / "gowitness.version.txt").read_text(encoding="utf-8", errors="replace")
            match = re.search(r"(?im)^\s*gowitness:\s*v?(\d+\.\d+\.\d+)\b", version_text)
            detected_version = match.group(1) if match else None
            if version_result.returncode or not match or match.group(1) != SUPPORTED_VERSION:
                return unavailable("Unsupported Gowitness version; this adapter requires 3.2.2. See gowitness.version.txt.")
            targets = workdir / "gowitness-targets.txt"
            with targets.open("x", encoding="utf-8") as stream:
                stream.write("\n".join(requested) + "\n")
            command = [self.executable, "scan", "file", "-f", str(targets),
                       "--screenshot-path", str(screenshot_dir), "--screenshot-format", "png",
                       "--write-jsonl", "--write-jsonl-file", str(metadata),
                       "--threads", str(self.threads), "--chrome-path", self.chrome_path, "--driver", self.driver,
                       "--log-scan-errors", "--skip-html", "--skip-network-logs"]
            if getattr(self, "proxy_url", None):
                command.extend(["--chrome-proxy", self.proxy_url])
                from .proxy import browser_command
                command[command.index("--chrome-path") + 1] = browser_command(self.chrome_path, workdir)
            issue = None
            for row in requested.values():
                row["capture_queued"] = True
            progress_metrics["launched"] = len(requested)
            monitor = _JsonlProgress(metadata, workdir, requested, callback, progress_metrics) if callable(callback) else None
            try:
                with (workdir / "gowitness.log").open("x", encoding="utf-8") as log:
                    outcome = _run_command(command, cancel_event=self.cancel_event, timeout=self.timeout,
                                           stdout=log, stderr=subprocess.STDOUT, shell=False, cwd=workdir,
                                           env=getattr(self, "proxy_environment", None),
                                           **({"on_tick": monitor.poll} if monitor is not None else {}))
                if outcome.returncode:
                    issue = self.exit_issue(workdir, outcome.returncode)
            except subprocess.TimeoutExpired:
                issue = "Gowitness capture exceeded its deadline; completed artifacts were retained. See gowitness.log."
            self._check_shutdown()
            if monitor is not None:
                monitor.poll()
            malformed, foreign, duplicates = _validate_metadata(metadata, workdir, requested, self._check_shutdown)
            detail = f"Captured {sum(row['status'] == 'captured' for row in requested.values())} of {len(requested)} HTTP-responsive endpoints; other attempts were skipped by preflight."
            if issue:
                detail += " " + issue
            if malformed or foreign or duplicates:
                detail += f" Ignored metadata: {malformed} malformed, {foreign} unrequested, {len(duplicates)} duplicate URLs."
            stage = self._stage(results, detail, issue=bool(issue or malformed or foreign or duplicates), version=detected_version)
            _report_progress(callback, "screenshots", current=len(requested), total=len(requested), metrics=stage)
            return results, stage
        except (FileNotFoundError, PermissionError) as error:
            return unavailable(f"Screenshot tooling or output path unavailable: {type(error).__name__}: {error}")
        except subprocess.TimeoutExpired:
            return unavailable("Gowitness version check exceeded its deadline.")
        except (OSError, ValueError) as error:
            detail = f"Screenshot capture could not complete: {type(error).__name__}: {error}"
            for row in requested.values():
                row.update(status="failed", relative_path=None, error=detail)
            stage = self._stage(results, detail, failed=True, version=detected_version)
            _report_progress(callback, "screenshots", current=len(requested), total=len(requested), metrics=stage)
            return results, stage

    @staticmethod
    def exit_issue(workdir, returncode):
        detail = f"Gowitness exited with code {returncode}; see gowitness.log."
        try:
            with (Path(workdir) / "gowitness.log").open("rb") as log:
                log.seek(0, 2)
                log.seek(max(0, log.tell() - 16384))
                tail = log.read(16384).decode("utf-8", errors="replace").lower()
            if "leakless" in tail and "permission denied" in tail:
                detail += (" Its Leakless browser helper was denied execution. A noexec /tmp mount can cause this; "
                           "recreate the container with the updated Compose /tmp:rw,exec,nosuid,nodev,mode=1777 mount.")
        except OSError:
            pass
        return detail

    def capture_stream(self, domains_iterator, workdir):
        """Capture qualified endpoints while a producer supplies resolving domains.

        Results remain provisional until the service reconciles final DNS facts.
        """
        from .capture_pipeline import capture_stream
        return capture_stream(self, domains_iterator, workdir)
