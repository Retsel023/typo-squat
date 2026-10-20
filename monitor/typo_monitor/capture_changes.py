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
    return (row.get("status") == "http_response" and 200 <= (row.get("title_http_status") or 0) < 300
            and (row.get("title_status") == "found" and bool(row.get("title"))
                 or row.get("title_status") == "missing" and not row.get("title")))


def _endpoint_complete(row):
    return (row.get("status") == "http_response" and row.get("title_status") in {"found", "missing"}
            and row.get("title_http_status") is not None and bool(row.get("title_url")))


def _same_endpoint(current, previous):
    return all(current.get(key) == previous.get(key) for key in
               ("title_url", "http_status", "title_http_status", "tls_verified"))


def _endpoint_changed(current, previous):
    # Absent legacy/title-read metadata is not evidence of a changed endpoint.
    return any(current.get(key) is not None and previous.get(key) is not None
               and current[key] != previous[key] for key in
               ("title_url", "http_status", "title_http_status", "tls_verified"))


def _structure_known(probe):
    from .page_structure import STRUCTURE_VERSION
    return (probe.get("body_status") == probe.get("page_structure_status") == "complete"
            and probe.get("page_structure_version") == STRUCTURE_VERSION
            and bool(probe.get("page_structure_sha256")))


def _same_structure(current, previous):
    return (_structure_known(current) and _structure_known(previous)
            and current["page_structure_sha256"] == previous["page_structure_sha256"])


def _route_key(route):
    return (bool(route.get("enabled")), route.get("endpoint") if route.get("enabled") else None)


def compare(capture, domain, row, diagnostic):
    """Compare each field to its latest trustworthy accepted observation.

    A skip additionally needs a successful, matching image baseline on disk.
    The old image is neither copied into this run nor attached to its report.
    """
    baseline = getattr(capture, "title_baselines", {}).get((domain, row["scheme"]), {})
    policy = getattr(capture, "capture_policy", {})
    text_mode = policy.get("comparison", "title") == "text"
    current_comparable = text_complete(diagnostic) if text_mode else _complete(diagnostic)
    latest, image = baseline.get("previous"), baseline.get("image")
    latest_probe = (latest or {}).get("preflight", {})
    title_old = baseline.get("title") or (latest if _complete(latest_probe) else None)
    text_old = baseline.get("text") or (latest if text_complete(latest_probe)
        and latest_probe.get("content_version") == diagnostic.get("content_version") else None)
    old = (text_old if text_mode else title_old) or latest
    previous = (old or {}).get("preflight", {})
    title_previous = (title_old or {}).get("preflight", {})
    connection_old = baseline.get("connection") or (latest if latest_probe.get("status")
        in {"http_response", "no_http_response"} else None)
    connection_previous = (connection_old or {}).get("preflight", {})
    endpoint_old = baseline.get("endpoint") or (latest if latest_probe.get("status") == "http_response" else None)
    endpoint_previous = (endpoint_old or {}).get("preflight", {})
    final_endpoint_old = endpoint_old if _endpoint_complete(endpoint_previous) else title_old
    final_endpoint_previous = (final_endpoint_old or {}).get("preflight", {})

    def reference(evidence):
        return {"run_id": evidence.get("run_id"),
                "checked_at": evidence.get("preflight", {}).get("checked_at") or evidence.get("captured_at")}

    diagnostic.update(web_change="unknown", connection_change=None, comparison_scope="content", comparison_mode="text" if text_mode else "title",
                      previous_title=previous.get("title"),
                      previous_title_status=previous.get("title_status"),
                      previous_content_status=previous.get("content_status"),
                      previous_duplicate_body_of=(latest or {}).get("preflight", {}).get("duplicate_body_of"),
                      previous_run_id=(old or {}).get("run_id"),
                      previous_known_title=title_previous.get("title"),
                      previous_known_title_status=title_previous.get("title_status"),
                      previous_endpoint={key: final_endpoint_previous.get(key) for key in
                                         ("title_url", "http_status", "title_http_status", "tls_verified")})
    diagnostic["comparison_baselines"] = {kind: reference(evidence) for kind, evidence in
        (("title", title_old), ("text", text_old if text_mode else None),
         ("connection", connection_old), ("endpoint", final_endpoint_old)) if evidence}
    diagnostic["previous_content_sha256"] = previous.get("content_sha256")
    stable_structure = (text_mode and text_complete(diagnostic) and text_complete(previous)
        and diagnostic.get("content_version") == previous.get("content_version")
        and _same_structure(diagnostic, previous) and _same_endpoint(diagnostic, previous)
        and _complete(title_previous) and diagnostic.get("title") == title_previous.get("title") == previous.get("title")
        and _route_key(baseline.get("text_route", {})) == _route_key(getattr(capture, "capture_route", {})))
    diagnostic["structure_comparison"] = ("unchanged" if _same_structure(diagnostic, previous) else
        "changed" if _structure_known(diagnostic) and _structure_known(previous) else "unavailable")
    if not previous:
        if current_comparable:
            diagnostic["web_change"] = "first_observation"
    elif text_mode and text_complete(diagnostic) and text_complete(previous) and diagnostic.get("content_version") == previous.get("content_version"):
        diagnostic["web_change"] = ("structure_changed" if diagnostic["structure_comparison"] == "changed" else
            "text_only_update" if stable_structure and diagnostic.get("text_sha256") != previous.get("text_sha256") else
            "text_changed" if diagnostic.get("text_sha256") != previous.get("text_sha256") else
            "structure_changed" if diagnostic.get("content_sha256") != previous.get("content_sha256") else "unchanged")
        if diagnostic.get("text_sha256") != previous.get("text_sha256"):
            diagnostic["text_diff"] = compact_diff(previous["page_text"], diagnostic["page_text"])
    elif text_mode and text_complete(diagnostic):
        diagnostic["web_change"] = "first_text_observation"
    elif not text_mode and _complete(diagnostic) and _complete(title_previous):
        diagnostic["web_change"] = "unchanged"
    elif not text_mode and _complete(diagnostic) and not _complete(title_previous):
        diagnostic["web_change"] = "first_title_observation"

    # Compare title/endpoint evidence independently of the text baseline: a
    # later title-only scan can update a title without erasing older full text.
    endpoint_changed = (diagnostic["status"] == endpoint_previous.get("status") == "http_response"
        and diagnostic.get("http_status") is not None and endpoint_previous.get("http_status") is not None
        and diagnostic["http_status"] != endpoint_previous["http_status"])
    if (_endpoint_complete(diagnostic) and _endpoint_complete(final_endpoint_previous)
            and _endpoint_changed(diagnostic, final_endpoint_previous)):
        endpoint_changed = True
    diagnostic["endpoint_change"] = "endpoint_changed" if endpoint_changed else None
    if (_complete(diagnostic) and _complete(title_previous)
            and diagnostic.get("title") != title_previous.get("title")):
        diagnostic["web_change"] = "title_changed"
    if {diagnostic["status"], connection_previous.get("status")} == {"http_response", "no_http_response"}:
        diagnostic["connection_change"] = ("became_available" if diagnostic["status"] == "http_response"
                                           else "became_unavailable")

    def recapture(reason):
        diagnostic.update(capture_decision="capture", capture_reason=reason)
        return False

    if diagnostic["status"] != "http_response":
        diagnostic.update(capture_decision="skip", capture_reason=diagnostic["status"])
        return False
    if policy.get("mode", "full") != "changes":
        return recapture("full_report")
    if diagnostic["web_change"] not in {"unchanged", "text_only_update"}:
        if diagnostic["web_change"] != "unknown":
            return recapture(diagnostic["web_change"])
        if not current_comparable:
            return recapture("current_text_uncertain" if text_mode else "current_title_uncertain")
        return recapture("previous_text_unavailable" if text_mode else "previous_title_unavailable")
    # Fresh comparable observations and a matching successful image are enough.
    # A failed intervening browser attempt does not invalidate that saved image.
    if not image:
        return recapture("image_baseline_missing")
    diagnostic["capture_baseline_run_id"] = image["run_id"]
    image_probe = image.get("preflight", {})
    # Retain the image's identity through prose-only skips. Otherwise the next
    # unchanged scan would recapture simply because its image has older wording.
    # Legacy images can be carried forward only through an exact text match or
    # an explicitly recorded earlier skip against that same image.
    structure_lineage = stable_structure and (
        previous.get("baseline_run_id") == image["run_id"]
        and previous.get("skip_reason") in {"unchanged_content", "text_only_update", "unchanged_structure"}
        or image_probe.get("content_sha256") == previous.get("content_sha256")
        and image_probe.get("content_version") == previous.get("content_version")
        and image_probe.get("title") == previous.get("title") and _same_endpoint(image_probe, previous))
    exact_content = (text_complete(image_probe) and image_probe.get("content_sha256") == diagnostic.get("content_sha256")
        and image_probe.get("content_version") == diagnostic.get("content_version"))
    if text_mode:
        # An exact prose hash must not overrule known layout differences (for
        # example, a prior browser failure after a stylesheet/markup change).
        comparable = text_complete(image_probe) and (
            _same_structure(diagnostic, image_probe) if _structure_known(image_probe)
            else exact_content or structure_lineage)
    else:
        comparable = _complete(image_probe)
    if (not comparable or image_probe.get("title") != diagnostic.get("title")
            or not _same_endpoint(diagnostic, image_probe)):
        return recapture("image_baseline_mismatch")
    # Moving the website stage to another proxy is a fresh browser baseline.
    if _route_key(baseline.get("route", {})) != _route_key(getattr(capture, "capture_route", {})):
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
    reason = ("text_only_update" if diagnostic["web_change"] == "text_only_update" else
              "unchanged_structure" if text_mode and not exact_content else
              "unchanged_content" if text_mode else "unchanged_title")
    diagnostic.update(skip_reason=reason, capture_decision="skip", capture_reason=reason, baseline_run_id=image["run_id"])
    return True


CHANGE_LABELS = {"first_observation": "First website observation", "first_title_observation": "First comparable title",
                 "first_text_observation": "First comparable page text", "text_changed": "Page text changed",
                 "structure_changed": "Static page structure, resources or form/link details changed",
                 "text_only_update": "Wording changed · static structure and title unchanged",
                 "title_changed": "Title changed",
                 "endpoint_changed": "HTTP endpoint changed", "became_available": "Website now responds",
                 "became_unavailable": "Website stopped responding"}

CONTENT_CHANGE_KINDS = frozenset({"first_observation", "first_title_observation", "first_text_observation",
                                  "text_changed", "structure_changed", "title_changed"})

CAPTURE_REASONS = {
    **CHANGE_LABELS,
    "full_report": "Full capture / report was requested; unchanged pages are captured too.",
    "periodic_refresh": "The saved screenshot reached the configured refresh age.",
    "current_title_uncertain": "The current static title check was incomplete or was not a successful 2xx response.",
    "current_text_uncertain": "The current static text check was incomplete or was not a successful 2xx response.",
    "previous_title_unavailable": "No comparable successful static title check was available in accepted history.",
    "previous_text_unavailable": "No comparable complete text check was available in accepted history.",
    "image_baseline_missing": "No successful saved screenshot baseline was available for this protocol.",
    "image_baseline_mismatch": "The saved screenshot's static title/content or HTTP endpoint did not match the fresh check.",
    "image_baseline_unavailable": "The saved screenshot file or its date/path metadata was unavailable or invalid.",
    "image_baseline_future_date": "The saved screenshot had a future timestamp; its age could not be trusted.",
    "proxy_route_changed": "The configured website proxy route changed since the saved screenshot.",
    "unchanged_title": "The fresh title and endpoint matched a valid saved screenshot; capture was skipped.",
    "unchanged_content": "The fresh content, title and endpoint matched a valid saved screenshot; capture was skipped.",
    "text_only_update": "Only extracted wording changed; the complete static structure, resources, forms/links, title and endpoint matched. Browser capture was skipped.",
    "unchanged_structure": "Static structure and title still match the saved image baseline; older wording does not require another browser capture.",
    "title_rule": "A configured title exclusion matched; capture was skipped.",
    "duplicate_body": "The complete fetched HTTP and HTTPS HTML matched; a duplicate browser capture was skipped.",
    "no_http_response": "No HTTP response was observed; capture was skipped.",
    "unknown": "The HTTP response check was uncertain; capture was skipped.",
}


def website_check_diagnostics(captures):
    """Summarize skipped transport checks separately from website review cards."""
    counts = {"no_http_response": 0, "unknown": 0}
    samples = []
    for capture in captures:
        probe = capture.get("preflight", {})
        status = probe.get("status")
        if status not in counts:
            continue
        counts[status] += 1
        if len(samples) < 20:
            samples.append({"domain": capture["domain"], "scheme": capture["scheme"],
                            "status": status, "error": probe.get("error") or capture.get("error"),
                            "became_unavailable": probe.get("connection_change", probe.get("web_change")) == "became_unavailable"})
    return {"counts": counts, "total": sum(counts.values()), "samples": samples}


def website_network_notes(captures):
    """Network-only differences are side notes, not website content changes."""
    total, samples = 0, []
    for capture in captures:
        probe = capture.get("preflight", {})
        kinds = [probe[key] for key in ("endpoint_change", "connection_change") if probe.get(key)]
        if not kinds and probe.get("web_change") in {"endpoint_changed", "became_available", "became_unavailable"}:
            kinds = [probe["web_change"]]
        if not kinds:
            continue
        total += 1
        if len(samples) < 20:
            samples.append({"domain": capture["domain"], "scheme": capture["scheme"],
                            "kinds": [CHANGE_LABELS.get(kind, kind) for kind in kinds],
                            "before": probe.get("previous_endpoint", {}),
                            "after": {key: probe.get(key) for key in
                                      ("title_url", "http_status", "title_http_status", "tls_verified")},
                            "error": probe.get("error")})
    return {"total": total, "samples": samples}


def website_text_notes(captures):
    """Keep minor prose diffs outside the main changes-only screenshot cards."""
    return sorted((capture for capture in captures
        if capture.get("preflight", {}).get("web_change") == "text_only_update"
        and capture.get("preflight", {}).get("skip_reason") not in {"title_rule", "duplicate_body"}
        and capture.get("preflight", {}).get("report_exclusion") != "browser_title_rule"),
        key=lambda capture: (capture["domain"], capture["scheme"]))


def report_entries(captures, mode="changes"):
    entries = []
    by_key = {(row["domain"], row["scheme"]): row for row in captures}
    for capture in captures:
        probe = capture.get("preflight", {})
        # Transport failures are diagnostic records, not website review entries.
        # Preserve older successful captures that predate preflight metadata.
        if probe.get("status") != "http_response" and not (
                not probe.get("status") and capture.get("status") == "captured" and capture.get("relative_path")):
            continue
        if probe.get("skip_reason") in {"title_rule", "duplicate_body"} or probe.get("report_exclusion") == "browser_title_rule":
            continue
        if mode == "changes" and probe.get("skip_reason") in {"unchanged_title", "unchanged_content", "unchanged_structure", "text_only_update"}:
            continue
        change = probe.get("web_change")
        label = CHANGE_LABELS.get(change)
        capture_reason = probe.get("capture_reason")
        if mode == "changes" and change not in CONTENT_CHANGE_KINDS:
            continue
        companion = by_key.get((capture["domain"], probe.get("body_shared_with")))
        if companion and companion.get("preflight", {}).get("duplicate_body_of") != capture["scheme"]:
            companion = None
        entries.append({"capture": capture, "reason": label or "Full report entry",
                        "schemes": ["http", "https"] if companion else [capture["scheme"]],
                        "protocol_observations": [capture, companion] if companion else [],
                        "capture_reason": CAPTURE_REASONS.get(capture_reason,
                            "This older scan did not record why the browser was requested."),
                        "before_title": probe.get("previous_known_title", probe.get("previous_title")), "after_title": probe.get("title"),
                        "previous_run_id": probe.get("previous_run_id")})
    return entries
