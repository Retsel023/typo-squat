"""Shared saved-image selection for inventory views and filters."""

from pathlib import Path
from uuid import UUID


def has_capture_image(capture):
    if not isinstance(capture, dict) or capture.get("status") != "captured":
        return False
    relative = capture.get("relative_path")
    if not isinstance(relative, str) or not relative or "\\" in relative:
        return False
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or path.suffix.lower() not in {".png", ".jpg", ".jpeg"}:
        return False
    try:
        UUID(capture.get("run_id", ""))
    except (ValueError, TypeError, AttributeError):
        return False
    return capture.get("scheme") in {"http", "https"}


def saved_capture(attempt):
    probe = attempt.get("preflight", {}) if isinstance(attempt, dict) else {}
    if probe.get("skip_reason") in {"title_rule", "duplicate_body"} or probe.get("report_exclusion") == "browser_title_rule":
        return None
    if has_capture_image(attempt):
        return attempt
    previous = attempt.get("previous_capture") if isinstance(attempt, dict) else None
    if previous and previous.get("preflight", {}).get("report_exclusion") == "browser_title_rule":
        return None
    if (has_capture_image(previous) and previous.get("domain") == attempt.get("domain")
            and previous.get("scheme") == attempt.get("scheme") and previous.get("project_id") == attempt.get("project_id")):
        return previous
    return None
