"""Bounded local telemetry explaining browser selection and title exclusions."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from .title_filter import filter_decision


LOG = logging.getLogger(__name__)


class CaptureDecisionLog:
    MAX_BYTES = 2 * 1024 * 1024

    def __init__(self, workdir, capture):
        self.capture, self.stream = capture, None
        try:
            # Exclusive creation rejects existing files and symlinks. The
            # caller has already validated the run's work directory.
            self.stream = (Path(workdir) / "capture-decisions.log").open("x+", encoding="ascii")
        except OSError:
            LOG.warning("Capture decision telemetry unavailable.")
        policy = getattr(capture, "title_filter", {})
        self.write(event="policy", title_exclusions_enabled=bool(policy.get("enabled")),
                   enabled_phrase_count=len(policy.get("rules", [])) if policy.get("enabled") else 0,
                   capture_mode=getattr(capture, "capture_policy", {}).get("mode", "full"))

    def write(self, **entry):
        if self.stream is None:
            return
        try:
            def small(value, depth=0):
                if value is None or type(value) in (bool, int, float):
                    return value
                if isinstance(value, dict) and depth < 3:
                    return {str(key)[:80]: small(item, depth + 1) for key, item in list(value.items())[:20]}
                return str(value)[:2048]
            # ASCII JSON escapes page-supplied controls and bounds each line.
            self.stream.write(json.dumps({"time": datetime.now(timezone.utc).isoformat(), **small(entry)},
                                         ensure_ascii=True) + "\n")
            if self.stream.tell() > self.MAX_BYTES:
                self.stream.seek(0)
                tail = self.stream.read()[-self.MAX_BYTES // 2:]
                tail = tail.partition("\n")[2]
                self.stream.seek(0)
                self.stream.truncate()
                self.stream.write(tail)
            self.stream.flush()
        except (OSError, ValueError):
            LOG.warning("Capture decision telemetry stopped; scan results are unaffected.")
            self.close()

    @staticmethod
    def fields(row):
        probe = row.get("preflight", {})
        return {"url": row["url"], "html_title": probe.get("title"),
                "html_title_status": probe.get("title_status", "disabled"),
                "html_filter": probe.get("title_filter"),
                "website_status": probe.get("status"),
                "final_html_url": probe.get("title_url"),
                "reason": probe.get("capture_reason"),
                "website_error": probe.get("error")}

    def before(self, row, selected):
        self.write(event="before_browser", action="selected_for_gowitness" if selected else "skipped_before_gowitness",
                   **self.fields(row))

    def browser_reported(self, record, requested):
        row = requested.get(record["url"])
        if row is None:
            return
        title = record.get("title") if isinstance(record.get("title"), str) else None
        domain = row["url"].split("://", 1)[1].rsplit(":", 1)[0]
        decision = filter_decision({"title": title, "title_status": "found" if title else "missing"},
            getattr(self.capture, "title_filter", {}),
            original=domain in getattr(self.capture, "original_domains", set()))
        decision["source"] = "browser"
        self.write(event="browser_reported", **self.fields(row),
                   browser_title=title[:1024] if title else None, browser_filter=decision,
                   screenshot_reported=bool(record.get("file_name")),
                   browser_failed=record.get("failed"), artifact_validation="pending",
                   note="The browser has already run; a rendered-title match cannot prevent this browser attempt.")

    def verified(self, requested):
        for row in requested.values():
            probe = row.get("preflight", {})
            excluded = probe.get("report_exclusion") == "browser_title_rule"
            self.write(event="verified_result", **self.fields(row),
                       browser_title=(row.get("title") or "")[:1024],
                       browser_filter=probe.get("browser_title_filter"),
                       saved_image=row.get("status") == "captured", capture_status=row.get("status"),
                       capture_queued=bool(row.get("capture_queued")),
                       title_excluded_from_report=excluded,
                       action="title_excluded_after_browser" if excluded else
                           "browser_title_not_excluded" if probe.get("browser_title_filter") else "browser_result_unavailable",
                       capture_error=row.get("error"))

    def close(self):
        if self.stream is not None:
            try:
                self.stream.close()
            except OSError:
                pass
            self.stream = None
