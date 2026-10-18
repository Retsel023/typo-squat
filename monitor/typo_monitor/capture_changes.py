"""Conservative text and title comparisons and change-only website reports."""

from datetime import datetime, timezone, timedelta
from pathlib import Path
import difflib
import textwrap


def normalize_policy(mode="changes", refresh_days=30, comparison="text"):
    if not isinstance(mode, str) or mode not in {"changes", "full"}:
        raise ValueError("Choose changes or full for capture_mode.")
    if type(refresh_days) is not int or not 0 <= refresh_days <= 365:
        raise ValueError("Screenshot refresh must be 0–365 days; 0 disables periodic recaptures.")
    if not isinstance(comparison, str) or comparison not in {"text", "title"}:
        raise ValueError("Choose text or title for comparison.")
    return {"mode": mode, "refresh_days": refresh_days, "comparison": comparison}


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
    diagnostic.update(web_change="unknown", previous_title=previous.get("title"),
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

    if (policy.get("mode", "full") != "changes" or diagnostic["web_change"] != "unchanged"
            or not image or not old or (old["status"] != "captured"
                and previous.get("skip_reason") not in {"unchanged_title", "unchanged_content"})):
        return False
    image_probe = image.get("preflight", {})
    comparable = (text_complete(image_probe) and image_probe.get("content_sha256") == diagnostic.get("content_sha256")
        and image_probe.get("content_version") == diagnostic.get("content_version")) if text_mode else _complete(image_probe)
    if (not comparable or image_probe.get("title") != diagnostic.get("title")
            or not _same_endpoint(diagnostic, image_probe)):
        return False
    # Moving the website stage to another proxy is a fresh browser baseline.
    def route_key(route):
        return (bool(route.get("enabled")), route.get("endpoint") if route.get("enabled") else None)
    if route_key(baseline.get("route", {})) != route_key(getattr(capture, "capture_route", {})):
        return False
    try:
        root = Path(capture.baseline_root).resolve()
        run_root = (root / "runs" / image["run_id"]).resolve()
        path = (run_root / image["relative_path"]).resolve()
        if not path.is_relative_to(run_root) or not run_root.is_relative_to(root) or not path.is_file():
            return False
        age = datetime.now(timezone.utc) - datetime.fromisoformat(image["captured_at"])
        if age < timedelta(0):
            return False
        refresh = policy.get("refresh_days", 30)
        if refresh and age >= timedelta(days=refresh):
            diagnostic["capture_reason"] = "periodic_refresh"
            return False
    except (AttributeError, KeyError, TypeError, ValueError, OSError, RuntimeError):
        return False
    diagnostic.update(skip_reason="unchanged_content" if text_mode else "unchanged_title", baseline_run_id=image["run_id"])
    return True


CHANGE_LABELS = {"first_observation": "First website observation", "first_title_observation": "First comparable title",
                 "first_text_observation": "First comparable page text", "text_changed": "Page text changed",
                 "structure_changed": "Form or link details changed",
                 "title_changed": "Title changed",
                 "endpoint_changed": "HTTP endpoint changed", "became_available": "Website now responds",
                 "became_unavailable": "Website stopped responding", "image_changed": "Image changed",
                 "first_image": "First screenshot"}


def report_entries(captures, mode="changes"):
    entries = []
    for capture in captures:
        probe, visual = capture.get("preflight", {}), capture.get("visual", {})
        if mode == "changes" and probe.get("skip_reason") in {"title_rule", "unchanged_title", "unchanged_content"}:
            continue
        change = probe.get("web_change")
        label = CHANGE_LABELS.get(change)
        if not label and capture["status"] == "captured":
            label = {"changed": "Image changed", "first_capture": "First screenshot"}.get(visual.get("change"))
        if mode == "changes" and not label:
            continue
        entries.append({"capture": capture, "reason": label or "Full report entry",
                        "before_title": probe.get("previous_title"), "after_title": probe.get("title"),
                        "previous_run_id": probe.get("previous_run_id"), "display_image": True})
    by_key = {(entry["capture"]["domain"], entry["capture"]["scheme"]): entry for entry in entries}
    for entry in entries:
        capture = entry["capture"]
        visual = capture.get("visual", {})
        # Collapse only identical current images of this same domain. Protocol
        # title histories remain separate entries even when pixels coincide.
        if capture["scheme"] != "http" or visual.get("duplicate_kind") != "exact" or visual.get("duplicate_of") != "https":
            continue
        other = by_key.get((capture["domain"], "https"), {}).get("capture", {})
        digest = visual.get("pixel_sha256")
        if (capture["status"] == other.get("status") == "captured" and digest
                and digest == other.get("visual", {}).get("pixel_sha256")):
            entry.update(display_image=False, duplicate_protocol="HTTPS")
    return entries
