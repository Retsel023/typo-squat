"""Client-readable CSV rows from saved observations; no scan or AI calls."""

import json

from .body_groups import group_report_entries
from .capture_changes import (CHANGE_LABELS, observed_title, report_entries, resolved_change,
                              review_priority, website_text_notes)
from .capture_images import has_capture_image, saved_capture
from .title_evidence import comparison_title


REPORT_FIELDS = ("section", "project", "scan_id", "scan_status", "scan_started_at", "domain", "protocol",
    "change", "priority", "previous_title", "current_title", "title_source", "dns_status", "dns_records",
    "before", "after", "http_status", "website_url", "screenshot_available", "screenshot_captured_at",
    "grouped_domains", "comparison_mode", "layout_similarity", "form_change", "page_text_diff", "saved_page_text", "details")
INVENTORY_DNS_FIELDS = ("latest_scan_id", "latest_dns_change", "previous_dns_records", "changed_dns_records")
INVENTORY_WEBSITE_FIELDS = ("http_title", "https_title", "http_status", "https_status",
    "http_screenshot_available", "https_screenshot_available", "http_screenshot_captured_at", "https_screenshot_captured_at",
    "http_last_website_check", "https_last_website_check", "http_website_change", "https_website_change")


def record_text(records):
    if isinstance(records, dict):
        records = records.get("records", [])
    values = []
    for record in records or []:
        if isinstance(record, dict):
            kind, value = record.get("type", ""), record.get("value", "")
        elif isinstance(record, (tuple, list)) and len(record) >= 2:
            kind, value = record[:2]
        else:
            kind, value = "", str(record)
        values.append(f"{kind} {value}".strip())
    return "; ".join(values)


def inventory_website_values(domain):
    values = dict.fromkeys(INVENTORY_WEBSITE_FIELDS, "")
    for capture in domain.get("screenshots", []):
        scheme = capture.get("scheme")
        if scheme not in {"http", "https"}:
            continue
        image = saved_capture(capture)
        title = observed_title(capture)
        if title["status"] != "found" and image:
            title = observed_title(image)
        probe = capture.get("preflight", {})
        values.update({f"{scheme}_title": title["title"] or "",
            f"{scheme}_status": probe.get("title_http_status") or capture.get("http_status") or "",
            f"{scheme}_screenshot_available": "yes" if image else "no",
            f"{scheme}_screenshot_captured_at": image.get("captured_at", "") if image else "",
            f"{scheme}_last_website_check": probe.get("checked_at") or capture.get("captured_at", ""),
            f"{scheme}_website_change": CHANGE_LABELS.get(resolved_change(capture), resolved_change(capture) or "")})
    return [values[field] for field in INVENTORY_WEBSITE_FIELDS]


def report_rows(project, run, captures, observations, *, website_view="priority", body_view="all"):
    """All matching report pages and side notes, one row per endpoint/event.

    Report screenshots always belong to this scan. Historical image fallback
    is reserved for the project's inventory CSV, just as in its gallery.
    """
    common = {"project": project["name"], "scan_id": run["id"], "scan_status": run["status"],
              "scan_started_at": run["started_at"]}
    yield {**common, "section": "scan_summary", "details":
        f"Website view: {website_view}; body view: {body_view}. "
        f"Saved DNS checks: {run.get('counts', {}).get('checked', 0)}. "
        "Observations do not establish a domain registration, purchase or maliciousness."}

    def dns(domain):
        observation = observations.get(domain, {})
        return {"dns_status": observation.get("status", ""), "dns_records": record_text(observation.get("records", []))}

    def website(capture, *, section, details="", group_domains=()):
        probe = capture.get("preflight", {})
        title = observed_title(capture)
        return {**common, **dns(capture["domain"]), "section": section, "domain": capture["domain"],
            "protocol": capture["scheme"].upper(), "change": resolved_change(capture) or "unknown",
            "priority": review_priority(capture)[0],
            "previous_title": comparison_title(probe.get("previous_known_title", probe.get("previous_title")), capture["domain"]) or "",
            "current_title": title["title"] or "", "title_source": title["source"],
            "http_status": probe.get("title_http_status") or capture.get("http_status") or "",
            "website_url": probe.get("title_url") or capture.get("url", ""),
            "screenshot_available": "yes" if has_capture_image(capture) else "no",
            "screenshot_captured_at": capture.get("captured_at", "") if has_capture_image(capture) else "",
            "grouped_domains": "; ".join(group_domains), "comparison_mode": probe.get("comparison_mode", ""),
            "layout_similarity": probe.get("layout_similarity"), "form_change": probe.get("form_change", ""),
            "page_text_diff": probe.get("text_diff", ""), "saved_page_text": probe.get("page_text", ""), "details": details}

    mode = "changes" if website_view == "priority" else "full"
    entries = report_entries(captures, mode)
    for entry in entries:
        entry["has_image"] = has_capture_image(entry["capture"])
    groups = group_report_entries(entries)
    seen = set()
    for group in groups:
        if not group["has_image"] or body_view != "all" and group["shared"] != (body_view == "shared"):
            continue
        domains = sorted({entry["capture"]["domain"] for entry in group["members"]})
        for entry in group["members"]:
            for capture in entry["protocol_observations"] or [entry["capture"]]:
                key = capture["domain"], capture["scheme"]
                if key not in seen:
                    seen.add(key)
                    yield website(capture, section="website", details=entry["review_reason"], group_domains=domains)
    # The screenshot-unavailable and context logs are independent of the
    # gallery's body filter and contain all pages, just like the HTML report.
    for entry in entries:
        capture = entry["capture"]
        key = capture["domain"], capture["scheme"]
        if not entry["has_image"] and key not in seen:
            seen.add(key)
            yield website(capture, section="screenshot_unavailable", details=entry["capture_reason"])
    if website_view == "priority":
        for group in website_text_notes(captures):
            for item in group["captures"]:
                yield website(item["capture"], section="page_context", details=item["review_reason"])
    for event in run.get("events", []):
        yield {**common, **dns(event["domain"]), "section": "dns_change", "domain": event["domain"],
            "change": event["kind"], "before": record_text(event.get("before", [])),
            "after": record_text(event.get("after", [])), "details": event.get("detail", "")}
    for capture in captures:
        probe = capture.get("preflight", {})
        changes = [probe[key] for key in ("endpoint_change", "connection_change") if probe.get(key)]
        if not changes and probe.get("web_change") in {"endpoint_changed", "became_available", "became_unavailable"}:
            changes = [probe["web_change"]]
        if changes:
            before = probe.get("previous_endpoint", {})
            after = {key: probe.get(key) for key in ("title_url", "http_status", "title_http_status", "tls_verified")}
            yield {**website(capture, section="network_note"), "change": "; ".join(changes),
                "before": json.dumps(before, ensure_ascii=False, sort_keys=True),
                "after": json.dumps(after, ensure_ascii=False, sort_keys=True),
                "details": "Network observation; not evidence of a website-content change or domain purchase."}
