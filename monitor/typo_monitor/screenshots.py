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
from .website_probe import WebsiteProbe, BROWSER_USER_AGENT
from .title_filter import MAX_TITLE_CHARS, TITLE_STATUSES, BODY_STATUSES, filter_decision
from .page_text import MAX_BODY_BYTES, MAX_TEXT_CHARS, TEXT_STATUSES
from .capture_decisions import CaptureDecisionLog


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
                or type(title_bytes) is not int or not 0 <= title_bytes <= MAX_BODY_BYTES):
            raise ValueError("Website preflight returned invalid title metadata.")
        validated[url].update(title=title, title_status=title_status, title_url=title_url,
                              title_http_status=title_code, title_bytes=title_bytes)
        body_hash, body_type = entry.get("body_sha256"), entry.get("body_content_type")
        body_status = entry.get("body_status", "complete" if body_hash else "disabled")
        if (body_hash is not None and (not isinstance(body_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", body_hash))
                or body_type is not None and (not isinstance(body_type, str) or len(body_type) > 256)
                or not isinstance(body_status, str) or body_status not in BODY_STATUSES
                or (body_status == "complete") != (body_hash is not None)):
            raise ValueError("Invalid complete-body fingerprint metadata.")
        validated[url].update(body_sha256=body_hash, body_content_type=body_type, body_status=body_status)
        from .page_structure import STRUCTURE_VERSION, STRUCTURE_STATUSES
        structure_hash = entry.get("page_structure_sha256")
        structure_version = entry.get("page_structure_version")
        structure_status = entry.get("page_structure_status", "unavailable")
        if (structure_hash is not None and (body_status != "complete" or not isinstance(structure_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}", structure_hash) or structure_version != STRUCTURE_VERSION)
                or structure_hash is None and structure_version is not None
                or not isinstance(structure_status, str) or structure_status not in STRUCTURE_STATUSES
                or (structure_status == "complete") != (structure_hash is not None)):
            raise ValueError("Invalid complete static page structure metadata.")
        validated[url].update(page_structure_sha256=structure_hash, page_structure_version=structure_version,
                              page_structure_status=structure_status)
        from .page_structure import validate_layout
        layout = entry.get("page_layout")
        validate_layout(layout)
        if layout is not None and (body_status != "complete" or structure_status != "complete"):
            raise ValueError("Static layout profiles require a complete HTML body and structure.")
        validated[url]["page_layout"] = layout
        template_hash = entry.get("body_template_sha256")
        template_version = entry.get("body_template_version")
        template_count = entry.get("body_template_replacements", 0)
        from .body_templates import TEMPLATE_VERSION
        if (template_hash is not None and (body_status != "complete" or not isinstance(template_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}", template_hash) or template_version != TEMPLATE_VERSION)
                or template_hash is None and template_version is not None
                or type(template_count) is not int or not 0 <= template_count <= MAX_BODY_BYTES
                or template_hash is None and template_count != 0):
            raise ValueError("Invalid complete HTML template fingerprint metadata.")
        validated[url].update(body_template_sha256=template_hash, body_template_version=template_version,
                              body_template_replacements=template_count)
        content_hash = entry.get("body_content_group_sha256")
        main_hash = entry.get("body_content_group_main_sha256")
        content_version = entry.get("body_content_group_version")
        consent_count = entry.get("body_content_group_ignored_consent", 0)
        group_status = entry.get("body_content_group_status", "complete" if content_hash else "unavailable")
        from .content_groups import CONTENT_GROUP_VERSION, CONTENT_GROUP_STATUSES
        if (content_hash is not None and (body_status != "complete" or not isinstance(content_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}", content_hash) or content_version != CONTENT_GROUP_VERSION)
                or content_hash is None and content_version is not None
                or main_hash is not None and (content_hash is None or not isinstance(main_hash, str)
                                             or not re.fullmatch(r"[0-9a-f]{64}", main_hash))
                or type(consent_count) is not int or not 0 <= consent_count <= MAX_BODY_BYTES
                or content_hash is None and consent_count != 0
                or not isinstance(group_status, str) or group_status not in CONTENT_GROUP_STATUSES
                or (group_status == "complete") != (content_hash is not None)):
            raise ValueError("Invalid main-content grouping metadata.")
        validated[url].update(body_content_group_sha256=content_hash, body_content_group_main_sha256=main_hash,
                              body_content_group_version=content_version,
                              body_content_group_ignored_consent=consent_count, body_content_group_status=group_status)
        content_status = entry.get("content_status", "disabled")
        page_text = entry.get("page_text", "")
        if (not isinstance(content_status, str) or content_status not in TEXT_STATUSES
                or not isinstance(page_text, str) or len(page_text) > MAX_TEXT_CHARS):
            raise ValueError("Website preflight returned invalid text metadata.")
        for key in ("text_sha256", "content_sha256", "forms_sha256"):
            value = entry.get(key)
            if value is not None and (not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)):
                raise ValueError("Website preflight returned invalid text fingerprints.")
        if content_status == "complete" and (not page_text or not entry.get("content_sha256") or not entry.get("text_sha256")):
            raise ValueError("Complete text requires saved text and fingerprints.")
        version = entry.get("content_version")
        if version is not None and (not isinstance(version, str) or len(version) > 80):
            raise ValueError("Invalid extraction version.")
        validated[url].update(content_status=content_status, page_text=page_text, content_version=version,
            text_sha256=entry.get("text_sha256"), content_sha256=entry.get("content_sha256"), forms_sha256=entry.get("forms_sha256"))
        for key in ("links", "forms"):
            values = entry.get(key, [])
            if not isinstance(values, list) or len(values) > 8 or any(not isinstance(value, str) or len(value) > 256 for value in values):
                raise ValueError("Invalid website text evidence.")
            count = entry.get(key + "_count", 0)
            if type(count) is not int or not 0 <= count <= 512:
                raise ValueError("Invalid website text evidence count.")
            validated[url].update({key: values, key + "_count": count})
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
    decision = filter_decision(diagnostic, getattr(capture, "title_filter", {}),
                               original=domain in getattr(capture, "original_domains", set()))
    diagnostic["title_filter"] = decision
    rule = decision["matched_rule"]
    if rule:
        scope = decision["scope"]
        diagnostic.update(skip_reason="title_rule", matched_rule=rule, rule_scope=scope,
                          capture_decision="skip", capture_reason="title_rule")
        row.update(status="skipped", error=f"Screenshot excluded by title rule: {rule} ({scope})",
                   captured_at=diagnostic["checked_at"])
        return False
    if unchanged:
        reason = {"unchanged_content": "Page content unchanged", "unchanged_title": "Title unchanged",
                  "text_only_update": "Only wording changed; static structure and title unchanged",
                  "minor_content_update": "Minor content changed; title and overall static layout matched",
                  "unchanged_structure": "Static structure and title unchanged"}[diagnostic["skip_reason"]]
        row.update(status="skipped", error=reason + "; no new screenshot requested.",
                   captured_at=diagnostic["checked_at"])
        return False
    return True


def _deduplicate_protocols(capture, rows, eligible):
    """Queue one browser only for complete, identical same-host HTML bodies."""
    from urllib.parse import urlsplit
    from .capture_changes import CHANGE_LABELS
    if len(rows) != 2:
        return

    def note(status, reason, differences=()):
        for row in rows:
            row["preflight"]["body_comparison"] = {"status": status, "reason": reason,
                                                    "differences": list(differences)}

    if not any(eligible.get(row["url"]) for row in rows):
        note("not_compared", "neither_protocol_needs_browser")
        return

    def identity(row):
        probe = row["preflight"]
        if (probe.get("status") != "http_response" or not probe.get("body_sha256")
                or probe.get("body_content_type") is None
                or probe.get("title_status") not in {"found", "missing"}):
            return None
        try:
            target = urlsplit(probe["title_url"])
            port = target.port
            if target.scheme not in {"http", "https"} or not target.hostname:
                return None
            port = None if port in {None, 80 if target.scheme == "http" else 443} else port
        except (KeyError, TypeError, ValueError):
            return None
        return (probe["body_sha256"], probe["body_content_type"], probe.get("title"),
                probe.get("title_http_status"), target.hostname, port, target.path or "/", target.query)

    first, second = map(identity, rows)
    if first is None or second is None:
        note("unavailable", "body_or_endpoint_metadata_incomplete")
        return
    if first != second:
        names = ("html_body", "content_type", "title", "final_http_status", "destination_host",
                 "destination_port", "destination_path", "destination_query")
        note("different", "comparison_fields_differ", [name for name, a, b in zip(names, first, second) if a != b])
        return
    # In a changelog keep an endpoint with an observed change as the image's
    # actual identity; otherwise prefer HTTPS. No cross-domain deduplication.
    changes = getattr(capture, "capture_policy", {}).get("mode") == "changes"
    if all(eligible.get(row["url"]) for row in rows):
        source = max(rows, key=lambda row: (changes and row["preflight"].get("web_change") in CHANGE_LABELS,
                                           row["scheme"] == "https"))
    else:
        candidate = next(row for row in rows if eligible.get(row["url"]))
        source = next(row for row in rows if row is not candidate)
        probe, baseline = candidate["preflight"], source["preflight"]
        # A deliberately skipped protocol must not force its missing image
        # to be captured on the next unchanged scan. The other protocol has
        # already passed compare()'s saved-image, route and age checks.
        if not (changes and probe.get("web_change") in {"unchanged", "text_only_update", "minor_content_update"}
                and probe.get("capture_reason") == "image_baseline_missing"
                and probe.get("previous_duplicate_body_of") == source["scheme"]
                and baseline.get("skip_reason") in {"unchanged_title", "unchanged_content", "unchanged_structure", "text_only_update", "minor_content_update"}):
            note("matched_capture_separate", "other_protocol_not_eligible_for_shared_capture")
            return
    note("matched", "shared_current_capture" if eligible.get(source["url"]) else "paired_unchanged_image_baseline")
    duplicate = next(row for row in rows if row is not source)
    duplicate["preflight"].update(skip_reason="duplicate_body", capture_decision="skip",
                                  capture_reason="duplicate_body", duplicate_body_of=source["scheme"])
    duplicate.update(status="skipped", captured_at=duplicate["preflight"]["checked_at"],
                     error=f"Complete fetched HTML matches {source['scheme'].upper()}; duplicate browser capture skipped.")
    source["preflight"]["body_shared_with"] = duplicate["scheme"]
    eligible[duplicate["url"]] = False


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


def _validate_metadata(metadata, workdir, requested, check_shutdown, *, title_filter=None, original_domains=()):
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
        # This title is only known after Chromium has run. Do not pretend its
        # screenshot was prevented, or delete already captured evidence.
        domain = url.split("://", 1)[1].rsplit(":", 1)[0]
        rendered = {"title": row["title"], "title_status": "found" if row["title"] else "missing"}
        decision = filter_decision(rendered, title_filter or {}, original=domain in original_domains)
        decision["source"] = "browser"
        probe = row.setdefault("preflight", {})
        probe["browser_title_filter"] = decision
        if decision["matched_rule"]:
            probe["report_exclusion"] = "browser_title_rule"
        try:
            relative_path = _image_path(workdir, record.get("file_name"))
        except (OSError, ValueError) as error:
            row["error"] = f"Screenshot artifact rejected: {error}"
            continue
        row.update(status="captured", relative_path=relative_path, error=None)
        from .capture_changes import reconcile_browser_title
        reconcile_browser_title(row)
    return malformed, foreign, duplicates


class _JsonlProgress:
    """Read bounded, complete records for telemetry; final validation stays separate."""

    _MAX_LINE = 1024 * 1024
    _MAX_TICK_BYTES = 4 * 1024 * 1024

    def __init__(self, path, workdir, requested, callback, metrics, on_result=None):
        self.path, self.workdir = path, workdir
        self.requested, self.callback = set(requested), callback
        self.metrics = dict(metrics)
        self.on_result = on_result
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
        first = url not in self.seen
        self.seen.add(url)
        if record.get("failed") is True:
            self.failed.add(url)
        if first and callable(self.on_result):
            try:
                self.on_result(record)
            except Exception:
                # Optional diagnostics cannot invalidate browser results.
                pass

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
    """Check both protocols, sharing captures for matching complete HTML.

    A supported Gowitness binary and an explicit or installed Chrome/Chromium
    binary are required. Browser downloads and filename inference are avoided.
    """

    def __init__(self, executable=None, chrome_path=None, timeout=900, threads=4, driver="gorod",
                 probe=None, probe_timeout=3, probe_workers=24, page_timeout=60, screenshot_delay=3):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Screenshot timeout must be positive and finite.")
        if not isinstance(threads, int) or isinstance(threads, bool) or not 1 <= threads <= 32:
            raise ValueError("Screenshot threads must be between 1 and 32.")
        if page_timeout is None or screenshot_delay is None:
            raise ValueError("Browser page timeout and screenshot delay require explicit integer values.")
        from .capture_changes import normalize_policy
        normalize_policy(page_timeout=page_timeout, screenshot_delay=screenshot_delay)
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
        self.page_timeout, self.screenshot_delay = page_timeout, screenshot_delay
        if driver not in {"gorod", "chromedp"}:
            raise ValueError("Capture driver must be gorod or chromedp.")
        self.driver = driver
        # Validate even when a fixture probe is injected; no network runs here.
        WebsiteProbe(timeout=probe_timeout, workers=probe_workers)
        self.probe = probe
        self.probe_timeout, self.probe_workers = probe_timeout, probe_workers
        self.cancel_event = None

    def performance_arguments(self):
        """The streamed and DNS-first paths use identical browser settings."""
        return ["--threads", str(self.threads), "--timeout", str(self.page_timeout),
                "--delay", str(self.screenshot_delay), "--chrome-user-agent", BROWSER_USER_AGENT]

    def performance_metrics(self):
        return {"browser_workers": self.threads, "page_timeout_seconds": self.page_timeout,
                "screenshot_delay_seconds": self.screenshot_delay, "web_workers": self.probe_workers}

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
        text_unchanged = sum(row.get("preflight", {}).get("skip_reason") == "unchanged_content" for row in rows)
        text_only_updates = sum(row.get("preflight", {}).get("skip_reason") == "text_only_update" for row in rows)
        minor_updates = sum(row.get("preflight", {}).get("skip_reason") == "minor_content_update" for row in rows)
        structure_unchanged = sum(row.get("preflight", {}).get("skip_reason") == "unchanged_structure" for row in rows)
        body_duplicates = sum(row.get("preflight", {}).get("skip_reason") == "duplicate_body" for row in rows)
        browser_filtered = sum(row.get("preflight", {}).get("report_exclusion") == "browser_title_rule" for row in rows)
        if title_filtered:
            detail += f" {title_filtered} endpoints excluded by configured title phrases; DNS inventory was retained."
        if title_unchanged:
            detail += f" {title_unchanged} endpoints had unchanged titles and did not request screenshots."
        if text_unchanged:
            detail += f" {text_unchanged} endpoints had unchanged page text and did not request screenshots."
        if text_only_updates:
            detail += f" {text_only_updates} wording-only updates skipped Gowitness; text diffs were retained."
        if minor_updates:
            detail += f" {minor_updates} minor page updates skipped Gowitness after title, key-element and overall-layout checks."
        if structure_unchanged:
            detail += f" {structure_unchanged} endpoints still matched their static structure/title baseline and skipped Gowitness."
        if body_duplicates:
            detail += f" {body_duplicates} duplicate browser requests skipped for matching HTTP/HTTPS bodies."
        if browser_filtered:
            detail += f" {browser_filtered} browser-title matches excluded from reports/AI after capture; any captured files retained in history."
        return {"status": "failed" if failed else "partial" if issue or unsuccessful or counts["unknown"] else "ok",
                "detail": detail, "version": version, "required_version": SUPPORTED_VERSION,
                "attempts": len(rows), "captured": captured,
                "failed": sum(row["status"] == "failed" for row in rows),
                "unavailable": sum(row["status"] == "unavailable" for row in rows),
                "eligible": counts["http_response"] - title_filtered - title_unchanged - text_unchanged - text_only_updates - minor_updates - structure_unchanged - body_duplicates,
                "title_filtered": title_filtered,
                "browser_title_filtered": browser_filtered,
                "body_duplicates": body_duplicates,
                "title_unchanged": title_unchanged,
                "text_unchanged": text_unchanged,
                "text_only_updates": text_only_updates,
                "minor_updates": minor_updates,
                "structure_unchanged": structure_unchanged,
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
        decisions = None
        if not requested:
            stage = self._stage(results, "No currently resolving candidates to capture.")
            return results, {**stage, "status": "skipped"}

        def unavailable(detail):
            for row in requested.values():
                row.update(status="unavailable", error=detail)
            if decisions is not None:
                decisions.verified(requested)
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
            decisions = CaptureDecisionLog(workdir, self)
            probe = self.probe or WebsiteProbe(timeout=self.probe_timeout, workers=self.probe_workers)
            probe.cancel_event = self.cancel_event
            probe.run_id = getattr(self, "run_id", "manual")
            probe.progress_callback = callback
            probe.proxy_url = getattr(self, "proxy_url", None)
            probe.collect_titles = bool(getattr(self, "collect_titles", False) or getattr(self, "title_filter", {}).get("enabled"))
            probe.collect_text = bool(getattr(self, "collect_text", False))
            diagnostics = probe.probe(list(requested))
            self._check_shutdown()
            try:
                diagnostics = _validated_preflight(diagnostics, requested)
            except ValueError as error:
                with preflight_file.open("x", encoding="utf-8") as stream:
                    json.dump({"error": str(error), "checked_at": _now()}, stream, indent=2)
                raise
            eligible = {}
            for url, diagnostic in diagnostics.items():
                row = requested[url]
                eligible[url] = _apply_preflight(self, row, diagnostic, url.split("://", 1)[1].rsplit(":", 1)[0])
            for rows in results.values():
                _deduplicate_protocols(self, rows, eligible)
                for row in rows:
                    decisions.before(row, eligible[row["url"]])
            with preflight_file.open("x", encoding="utf-8") as stream:
                json.dump(diagnostics, stream, indent=2)
            requested = {url: row for url, row in requested.items() if eligible[url]}
            progress_metrics = {**self.performance_metrics(), "eligible": len(requested), "launched": 0,
                                "body_duplicates": sum(row.get("preflight", {}).get("skip_reason") == "duplicate_body" for rows in results.values() for row in rows),
                                "title_filtered": sum(row.get("preflight", {}).get("skip_reason") == "title_rule" for rows in results.values() for row in rows),
                                "title_unchanged": sum(row.get("preflight", {}).get("skip_reason") == "unchanged_title" for rows in results.values() for row in rows),
                                "text_unchanged": sum(row.get("preflight", {}).get("skip_reason") == "unchanged_content" for rows in results.values() for row in rows),
                                "text_only_updates": sum(row.get("preflight", {}).get("skip_reason") == "text_only_update" for rows in results.values() for row in rows),
                                "minor_updates": sum(row.get("preflight", {}).get("skip_reason") == "minor_content_update" for rows in results.values() for row in rows),
                                "structure_unchanged": sum(row.get("preflight", {}).get("skip_reason") == "unchanged_structure" for rows in results.values() for row in rows),
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
                       *self.performance_arguments(), "--chrome-path", self.chrome_path, "--driver", self.driver,
                       "--log-scan-errors", "--skip-html", "--skip-network-logs"]
            if getattr(self, "proxy_url", None):
                command.extend(["--chrome-proxy", self.proxy_url])
                from .proxy import browser_command
                command[command.index("--chrome-path") + 1] = browser_command(self.chrome_path, workdir)
            issue = None
            for row in requested.values():
                row["capture_queued"] = True
            progress_metrics["launched"] = len(requested)
            monitor = _JsonlProgress(metadata, workdir, requested, callback, progress_metrics,
                on_result=lambda record: decisions.browser_reported(record, requested))
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
            malformed, foreign, duplicates = _validate_metadata(metadata, workdir, requested, self._check_shutdown,
                title_filter=getattr(self, "title_filter", {}), original_domains=getattr(self, "original_domains", set()))
            decisions.verified(requested)
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
            if decisions is not None:
                decisions.verified(requested)
            stage = self._stage(results, detail, failed=True, version=detected_version)
            _report_progress(callback, "screenshots", current=len(requested), total=len(requested), metrics=stage)
            return results, stage
        finally:
            if decisions is not None:
                decisions.close()

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
