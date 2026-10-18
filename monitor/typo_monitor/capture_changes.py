"""Conservative text and title comparisons and change-only website reports."""

from datetime import datetime, timezone, timedelta
from pathlib import Path
import difflib
import textwrap


PERFORMANCE_LIMITS = {"browser_workers": (1, 32), "page_timeout": (5, 180),
                      "screenshot_delay": (0, 30), "web_workers": (1, 128)}
PERFORMANCE_DEFAULTS = {"browser_workers": 4, "page_timeout": 60, "screenshot_delay": 3, "web_workers": 24}


def normalize_policy(mode="changes", refresh_days=30, comparison="text", *, browser_workers=None,
                     page_timeout=None, screenshot_delay=None, web_workers=None):
    if not isinstance(mode, str) or mode not in {"changes", "full"}:
        raise ValueError("Choose changes or full for capture_mode.")
    if type(refresh_days) is not int or not 0 <= refresh_days <= 365:
        raise ValueError("Screenshot refresh must be 0–365 days; 0 disables periodic recaptures.")
    if not isinstance(comparison, str) or comparison not in {"text", "title"}:
        raise ValueError("Choose text or title for comparison.")
    result = {"mode": mode, "refresh_days": refresh_days, "comparison": comparison,
              "browser_workers": browser_workers, "page_timeout": page_timeout,
              "screenshot_delay": screenshot_delay, "web_workers": web_workers}
    for name, (minimum, maximum) in PERFORMANCE_LIMITS.items():
        value = result[name]
        if value is not None and (type(value) is not int or not minimum <= value <= maximum):
            raise ValueError(f"{name.replace('_', ' ')} must be a whole number from {minimum} to {maximum}, or blank for the server default.")
    if page_timeout is not None and screenshot_delay is not None and screenshot_delay >= page_timeout:
        raise ValueError("Screenshot delay must be shorter than the page timeout.")
    return result


def text_complete(row):
    return (row.get("status") == "http_response" and row.get("content_status") == "complete"
            and bool(row.get("page_text")) and bool(row.get("content_sha256"))
            and row.get("title_status") in {"found", "missing"}
            and 200 <= (row.get("title_http_status") or 0) < 300)


def compact_diff(previous, current):
    before, after = textwrap.wrap(previous, 120), textwrap.wrap(current, 120)
    result, size = [], 0
    for line in difflib.unified_diff(before, after, fromfile="previous", tofile="current", n=1, lineterm=""):
        if size + len(line) + 1 > 2500:
            result.append("[diff truncated; full text remains in local reports]")
            break
        result.append(line)
        size += len(line) + 1
    return "\n".join(result)


def _complete(row):
    return (row.get("status") == "http_response" and row.get("title_status") == "found"
            and bool(row.get("title")) and 200 <= (row.get("title_http_status") or 0) < 300)


def _same_endpoint(current, previous):
    return all(current.get(key) == previous.get(key) for key in
               ("title_url", "http_status", "title_http_status", "tls_verified"))


def _endpoint_changed(current, previous):
    # Absent legacy/title-read metadata is not evidence of a changed endpoint.
    return any(current.get(key) is not None and previous.get(key) is not None
               and current[key] != previous[key] for key in
               ("title_url", "http_status", "title_http_status", "tls_verified"))


def compare(capture, domain, row, diagnostic):
    """Annotate against the previous accepted run; never guess at missing data.

    A skip additionally needs a successful, matching image baseline on disk.
    The old image is neither copied into this run nor attached to its report.
    """
    baseline = getattr(capture, "title_baselines", {}).get((domain, row["scheme"]), {})
    old, image = baseline.get("previous"), baseline.get("image")
    previous = (old or {}).get("preflight", {})
    policy = getattr(capture, "capture_policy", {})
    text_mode = policy.get("comparison", "title") == "text"
    diagnostic.update(web_change="unknown", comparison_mode="text" if text_mode else "title",
                      previous_title=previous.get("title"),
                      previous_title_status=previous.get("title_status"),
                      previous_content_status=previous.get("content_status"),
                      previous_run_id=(old or {}).get("run_id"),
                      previous_endpoint={key: previous.get(key) for key in
                                         ("title_url", "http_status", "title_http_status", "tls_verified")})
    diagnostic["previous_content_sha256"] = previous.get("content_sha256")
    if not previous:
        if diagnostic["status"] == "http_response":
            diagnostic["web_change"] = "first_observation"
    elif {diagnostic["status"], previous.get("status")} == {"http_response", "no_http_response"}:
        diagnostic["web_change"] = ("became_available" if diagnostic["status"] == "http_response"
                                    else "became_unavailable")
    elif text_mode and text_complete(diagnostic) and text_complete(previous) and diagnostic.get("content_version") == previous.get("content_version"):
        diagnostic["web_change"] = ("title_changed" if diagnostic.get("title") != previous.get("title") else
            "endpoint_changed" if not _same_endpoint(diagnostic, previous) else
            "text_changed" if diagnostic.get("text_sha256") != previous.get("text_sha256") else
            "structure_changed" if diagnostic.get("content_sha256") != previous.get("content_sha256") else "unchanged")
        if diagnostic.get("text_sha256") != previous.get("text_sha256"):
            diagnostic["text_diff"] = compact_diff(previous["page_text"], diagnostic["page_text"])
    elif text_mode and text_complete(diagnostic):
        diagnostic["web_change"] = "first_text_observation"
    elif not text_mode and _complete(diagnostic) and _complete(previous):
        diagnostic["web_change"] = ("title_changed" if diagnostic["title"] != previous["title"] else
                                    "endpoint_changed" if not _same_endpoint(diagnostic, previous) else "unchanged")
    elif (diagnostic["status"] == previous.get("status") == "http_response"
          and _endpoint_changed(diagnostic, previous)):
        diagnostic["web_change"] = "endpoint_changed"
    elif not text_mode and _complete(diagnostic) and not _complete(previous):
        diagnostic["web_change"] = "first_title_observation"

    def recapture(reason):
        diagnostic.update(capture_decision="capture", capture_reason=reason)
        return False

    if diagnostic["status"] != "http_response":
        diagnostic.update(capture_decision="skip", capture_reason=diagnostic["status"])
        return False
    if policy.get("mode", "full") != "changes":
        return recapture("full_report")
    if diagnostic["web_change"] != "unchanged":
        if diagnostic["web_change"] != "unknown":
            return recapture(diagnostic["web_change"])
        if not (text_complete(diagnostic) if text_mode else _complete(diagnostic)):
            return recapture("current_text_uncertain" if text_mode else "current_title_uncertain")
        return recapture("previous_text_unavailable" if text_mode else "previous_title_unavailable")
    # Fresh comparable observations and a matching successful image are enough.
    # A failed intervening browser attempt does not invalidate that saved image.
    if not image:
        return recapture("image_baseline_missing")
    diagnostic["capture_baseline_run_id"] = image["run_id"]
    image_probe = image.get("preflight", {})
    comparable = (text_complete(image_probe) and image_probe.get("content_sha256") == diagnostic.get("content_sha256")
        and image_probe.get("content_version") == diagnostic.get("content_version")) if text_mode else _complete(image_probe)
    if (not comparable or image_probe.get("title") != diagnostic.get("title")
            or not _same_endpoint(diagnostic, image_probe)):
        return recapture("image_baseline_mismatch")
    # Moving the website stage to another proxy is a fresh browser baseline.
    def route_key(route):
        return (bool(route.get("enabled")), route.get("endpoint") if route.get("enabled") else None)
    if route_key(baseline.get("route", {})) != route_key(getattr(capture, "capture_route", {})):
        return recapture("proxy_route_changed")
    try:
        root = Path(capture.baseline_root).resolve()
        run_root = (root / "runs" / image["run_id"]).resolve()
        path = (run_root / image["relative_path"]).resolve()
        if not path.is_relative_to(run_root) or not run_root.is_relative_to(root) or not path.is_file():
            return recapture("image_baseline_unavailable")
        age = datetime.now(timezone.utc) - datetime.fromisoformat(image["captured_at"])
        if age < timedelta(0):
            return recapture("image_baseline_future_date")
        refresh = policy.get("refresh_days", 30)
        if refresh and age >= timedelta(days=refresh):
            return recapture("periodic_refresh")
    except (AttributeError, KeyError, TypeError, ValueError, OSError, RuntimeError):
        return recapture("image_baseline_unavailable")
    reason = "unchanged_content" if text_mode else "unchanged_title"
    diagnostic.update(skip_reason=reason, capture_decision="skip", capture_reason=reason, baseline_run_id=image["run_id"])
    return True


CHANGE_LABELS = {"first_observation": "First website observation", "first_title_observation": "First comparable title",
                 "first_text_observation": "First comparable page text", "text_changed": "Page text changed",
                 "structure_changed": "Form or link details changed",
                 "title_changed": "Title changed",
                 "endpoint_changed": "HTTP endpoint changed", "became_available": "Website now responds",
                 "became_unavailable": "Website stopped responding"}

CAPTURE_REASONS = {
    **CHANGE_LABELS,
    "full_report": "Full capture / report was requested; unchanged pages are captured too.",
    "periodic_refresh": "The saved screenshot reached the configured refresh age.",
    "current_title_uncertain": "The current static title check was incomplete or was not a successful 2xx response.",
    "current_text_uncertain": "The current static text check was incomplete or was not a successful 2xx response.",
    "previous_title_unavailable": "There was no comparable successful static title check in the previous accepted run.",
    "previous_text_unavailable": "There was no comparable complete text check in the previous accepted run.",
    "image_baseline_missing": "No successful saved screenshot baseline was available for this protocol.",
    "image_baseline_mismatch": "The saved screenshot's static title/content or HTTP endpoint did not match the fresh check.",
    "image_baseline_unavailable": "The saved screenshot file or its date/path metadata was unavailable or invalid.",
    "image_baseline_future_date": "The saved screenshot had a future timestamp; its age could not be trusted.",
    "proxy_route_changed": "The configured website proxy route changed since the saved screenshot.",
    "unchanged_title": "The fresh title and endpoint matched a valid saved screenshot; capture was skipped.",
    "unchanged_content": "The fresh content, title and endpoint matched a valid saved screenshot; capture was skipped.",
    "title_rule": "A configured title exclusion matched; capture was skipped.",
    "no_http_response": "No HTTP response was observed; capture was skipped.",
    "unknown": "The HTTP response check was uncertain; capture was skipped.",
}


def report_entries(captures, mode="changes"):
    entries = []
    for capture in captures:
        probe = capture.get("preflight", {})
        if mode == "changes" and probe.get("skip_reason") in {"title_rule", "unchanged_title", "unchanged_content"}:
            continue
        change = probe.get("web_change")
        label = CHANGE_LABELS.get(change)
        capture_reason = probe.get("capture_reason")
        if mode == "changes" and not label:
            continue
        entries.append({"capture": capture, "reason": label or "Full report entry",
                        "capture_reason": CAPTURE_REASONS.get(capture_reason,
                            "This older scan did not record why the browser was requested."),
                        "before_title": probe.get("previous_title"), "after_title": probe.get("title"),
                        "previous_run_id": probe.get("previous_run_id")})
    return entries
