"""Conservative title comparisons and change-only website reports."""

from datetime import datetime, timezone, timedelta
from pathlib import Path


def normalize_policy(mode="changes", refresh_days=30):
    if not isinstance(mode, str) or mode not in {"changes", "full"}:
        raise ValueError("Choose changes or full for capture_mode.")
    if type(refresh_days) is not int or not 0 <= refresh_days <= 365:
        raise ValueError("Screenshot refresh must be 0–365 days; 0 disables periodic recaptures.")
    return {"mode": mode, "refresh_days": refresh_days}


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
    diagnostic.update(web_change="unknown", previous_title=previous.get("title"),
                      previous_run_id=(old or {}).get("run_id"),
                      previous_endpoint={key: previous.get(key) for key in
                                         ("title_url", "http_status", "title_http_status", "tls_verified")})
    if not previous:
        if diagnostic["status"] == "http_response":
            diagnostic["web_change"] = "first_observation"
    elif {diagnostic["status"], previous.get("status")} == {"http_response", "no_http_response"}:
        diagnostic["web_change"] = ("became_available" if diagnostic["status"] == "http_response"
                                    else "became_unavailable")
    elif _complete(diagnostic) and _complete(previous):
        diagnostic["web_change"] = ("title_changed" if diagnostic["title"] != previous["title"] else
                                    "endpoint_changed" if not _same_endpoint(diagnostic, previous) else "unchanged")
    elif (diagnostic["status"] == previous.get("status") == "http_response"
          and _endpoint_changed(diagnostic, previous)):
        diagnostic["web_change"] = "endpoint_changed"
    elif _complete(diagnostic) and not _complete(previous):
        diagnostic["web_change"] = "first_title_observation"

    policy = getattr(capture, "capture_policy", {})
    if (policy.get("mode", "full") != "changes" or diagnostic["web_change"] != "unchanged"
            or not image or not old or (old["status"] != "captured"
                and previous.get("skip_reason") != "unchanged_title")):
        return False
    image_probe = image.get("preflight", {})
    if (not _complete(image_probe) or image_probe["title"] != diagnostic["title"]
            or not _same_endpoint(diagnostic, image_probe)):
        return False
    # Moving the website stage to another proxy is a fresh browser baseline.
    if baseline.get("route") != getattr(capture, "capture_route", {}):
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
    diagnostic.update(skip_reason="unchanged_title", baseline_run_id=image["run_id"])
    return True


CHANGE_LABELS = {"first_observation": "First website observation", "first_title_observation": "First comparable title",
                 "title_changed": "Title changed",
                 "endpoint_changed": "HTTP endpoint changed", "became_available": "Website now responds",
                 "became_unavailable": "Website stopped responding", "image_changed": "Image changed",
                 "first_image": "First screenshot"}


def report_entries(captures, mode="changes"):
    entries = []
    for capture in captures:
        probe, visual = capture.get("preflight", {}), capture.get("visual", {})
        if mode == "changes" and probe.get("skip_reason") in {"title_rule", "unchanged_title"}:
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
