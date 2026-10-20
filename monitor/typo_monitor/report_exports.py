"""Domain-grouped client exports from saved observations; no scan or AI calls."""

from datetime import datetime, timezone

from .body_groups import group_report_entries
from .capture_changes import (CHANGE_LABELS, observed_title, report_entries, resolved_change,
                              review_priority, website_text_notes)
from .capture_images import has_capture_image, saved_capture
from .title_evidence import comparison_title


CLIENT_FIELDS = ("Project", "Domain", "Scan date", "Findings", "DNS status", "DNS before", "DNS now", "Websites", "Screenshots", "Notes")
_DNS_LABELS = {"resolved": "Resolves", "pending_missing": "Awaiting DNS confirmation", "missing": "DNS absence confirmed",
               "unknown": "DNS uncertain", "nxdomain": "NXDOMAIN", "noanswer": "No DNS answer"}
_CHANGES = {**CHANGE_LABELS, "newly_observed": "New DNS observation", "records_changed": "DNS records changed",
            "missing_confirmed": "DNS absence confirmed", "reappeared": "Resolves again", "unchanged": "Unchanged",
            "unknown": "Check uncertain", "title_unavailable": "Title unavailable", "title_recovered": "Title recovered"}


def display_date(value):
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is not None:
            stamp = stamp.astimezone(timezone.utc)
        return stamp.strftime("%d %b %Y %H:%M UTC")
    except (AttributeError, ValueError, TypeError):
        return "Not recorded"


def _append(values, value):
    if value and value not in values:
        values.append(value)


def _client_record(domain):
    return {"domain": domain, "findings": [], "dns_status": "", "dns_before": "", "dns_now": "",
            "endpoints": {}, "notes": [], "sources": [], "priority": "other"}


def _endpoint(capture, *, image=None):
    probe = capture.get("preflight", {})
    title = observed_title(capture)
    if title["status"] != "found" and image:
        title = observed_title(image)
    code = probe.get("title_http_status") or capture.get("http_status")
    return {"title": title["title"] or "Title unavailable", "previous_title": comparison_title(
                probe.get("previous_known_title", probe.get("previous_title")), capture["domain"]),
            "status": f"HTTP {code}" if code else "No HTTP response" if probe.get("status") == "no_http_response" else "Response uncertain",
            "url": probe.get("title_url") or capture.get("url", ""), "image": image,
            "previous_image": bool(image and image.get("run_id") != capture.get("run_id")),
            "checked_at": probe.get("checked_at") or capture.get("captured_at"),
            "shared_with": probe.get("duplicate_body_of") if probe.get("skip_reason") == "duplicate_body" else None}


def inventory_records(domains):
    """Keep the selected inventory order, with both protocols in one record."""
    for domain in domains:
        row = _client_record(domain["domain"])
        row.update(dns_status=_DNS_LABELS.get(domain.get("status"), "DNS uncertain"),
                   dns_now=record_text(domain.get("records")), sources=domain.get("sources", []))
        if domain.get("latest_observation") in {"nxdomain", "noanswer"}:
            row["dns_now"] = "No current DNS answer" + (". Last known: " + row["dns_now"] if row["dns_now"] else "")
        elif domain.get("latest_observation") == "unknown" and row["dns_now"]:
            row["dns_now"] = "Current check uncertain. Last known: " + row["dns_now"]
        event = domain.get("latest_dns_event") or {}
        if event:
            row["dns_before"] = record_text(event.get("before"))
            _append(row["findings"], _CHANGES.get(event.get("kind"), "DNS change"))
        parking = domain.get("parking") or {}
        if parking.get("status") == "likely_parked":
            _append(row["notes"], "Likely parked" + (" - " + parking["provider"] if parking.get("provider") else ""))
        for note in parking.get("evidence", []) if isinstance(parking.get("evidence"), list) else [parking.get("evidence")]:
            _append(row["notes"], note)
        _append(row["notes"], domain.get("last_error"))
        if domain.get("is_seed"):
            _append(row["notes"], "Original domain")
        for capture in domain.get("screenshots", []):
            scheme = capture.get("scheme")
            if scheme not in {"http", "https"}:
                continue
            row["endpoints"][scheme] = _endpoint(capture, image=saved_capture(capture))
            change = resolved_change(capture)
            if change and change != "unchanged":
                _append(row["findings"], f"{scheme.upper()}: {_CHANGES.get(change, change.replace('_', ' ').capitalize())}")
        yield row


def report_records(project, run, captures, observations, *, website_view="priority", body_view="all"):
    """Merge website, DNS and side-note rows without duplicating a domain."""
    records = {}
    by_key = {(capture["domain"], capture["scheme"]): capture for capture in captures}
    ranks = {"new": 0, "major": 1, "context": 2, "other": 3}
    for item in _report_observations(run, captures, observations, website_view=website_view, body_view=body_view):
        row = records.setdefault(item["domain"], _client_record(item["domain"]))
        row["dns_status"] = _DNS_LABELS.get(item.get("dns_status"), item.get("dns_status") or "Not checked")
        row["dns_now"] = item.get("dns_records") or row["dns_now"]
        if item["section"] == "dns_change":
            row.update(dns_before=item.get("before", ""), dns_now=item.get("after", ""))
            _append(row["findings"], _CHANGES.get(item["change"], item["change"]))
        else:
            scheme = item.get("protocol", "").lower()
            capture = by_key.get((item["domain"], scheme))
            if capture:
                image = capture if item["section"] == "website" and has_capture_image(capture) else None
                endpoint = _endpoint(capture, image=image)
                old = row["endpoints"].get(scheme)
                if old and old.get("image") and image is None:
                    endpoint["image"] = old["image"]
                    endpoint["previous_image"] = old["previous_image"]
                row["endpoints"][scheme] = endpoint
            if item["section"] == "network_note":
                _append(row["notes"], f"{scheme.upper()}: " + item["change"].replace("_", " "))
            else:
                label = _CHANGES.get(item.get("change"), item.get("details") or "Website observation")
                _append(row["findings"], f"{scheme.upper()}: {label}")
            priority = item.get("priority", "other")
            if ranks.get(priority, 3) < ranks[row["priority"]]:
                row["priority"] = priority
        if item["section"] not in {"network_note", "dns_change"}:
            _append(row["notes"], item.get("details"))
    for row in records.values():
        for scheme in ("http", "https"):
            capture = by_key.get((row["domain"], scheme))
            if capture and scheme not in row["endpoints"]:
                # DNS-only notes can still show the saved website checks, but
                # must not promote their images into the priority report.
                row["endpoints"][scheme] = _endpoint(capture)
    return sorted(records.values(), key=lambda row: (ranks[row["priority"]], row["domain"]))


def client_csv_rows(project, records, *, scan=None):
    """Human-readable cells: HTTP first, then HTTPS in the same columns."""
    for row in records:
        websites, screenshots = [], []
        for scheme in ("http", "https"):
            endpoint = row["endpoints"].get(scheme)
            if not endpoint:
                continue
            details = f"{scheme.upper()}: {endpoint['title']}\n{endpoint['status']} - {endpoint['url']}"
            if endpoint.get("previous_title") and endpoint["previous_title"] != endpoint["title"]:
                details += "\nPrevious title: " + endpoint["previous_title"]
            websites.append(details)
            image = endpoint.get("image")
            status = (("Previous capture " if endpoint.get("previous_image") else "Captured ") + display_date(image.get("captured_at"))) if image else (
                "Same HTML as " + endpoint["shared_with"].upper() if endpoint.get("shared_with") else "No saved screenshot")
            screenshots.append(f"{scheme.upper()}: {status}")
        notes = list(row["notes"])
        if row["sources"]:
            notes.insert(0, "Generated from: " + "; ".join(row["sources"]))
        yield {"Project": project["name"], "Domain": row["domain"], "Scan date": display_date(scan.get("started_at")) if scan else "Not recorded",
            "Findings": "\n".join(row["findings"]),
            "DNS status": row["dns_status"], "DNS before": row["dns_before"], "DNS now": row["dns_now"],
            "Websites": "\n\n".join(websites), "Screenshots": "\n".join(screenshots), "Notes": "\n".join(notes)}


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


def _report_observations(run, captures, observations, *, website_view="priority", body_view="all"):
    """All matching report pages and side notes, one row per endpoint/event.

    Report screenshots always belong to this scan. Historical image fallback
    is reserved for the project's inventory exports, just as in its gallery.
    """
    def dns(domain):
        observation = observations.get(domain, {})
        return {"dns_status": observation.get("status", ""), "dns_records": record_text(observation.get("records", []))}

    def website(capture, *, section, details=""):
        return {**dns(capture["domain"]), "section": section, "domain": capture["domain"],
            "protocol": capture["scheme"].upper(), "change": resolved_change(capture) or "unknown",
            "priority": review_priority(capture)[0], "details": details}

    mode = "changes" if website_view == "priority" else "full"
    entries = report_entries(captures, mode)
    for entry in entries:
        entry["has_image"] = has_capture_image(entry["capture"])
    groups = group_report_entries(entries)
    seen = set()
    for group in groups:
        if not group["has_image"] or body_view != "all" and group["shared"] != (body_view == "shared"):
            continue
        for entry in group["members"]:
            for capture in entry["protocol_observations"] or [entry["capture"]]:
                key = capture["domain"], capture["scheme"]
                if key not in seen:
                    seen.add(key)
                    yield website(capture, section="website", details=entry["review_reason"])
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
        yield {**dns(event["domain"]), "section": "dns_change", "domain": event["domain"],
            "change": event["kind"], "before": record_text(event.get("before", [])),
            "after": record_text(event.get("after", [])), "details": event.get("detail", "")}
    for capture in captures:
        probe = capture.get("preflight", {})
        changes = [probe[key] for key in ("endpoint_change", "connection_change") if probe.get(key)]
        if not changes and probe.get("web_change") in {"endpoint_changed", "became_available", "became_unavailable"}:
            changes = [probe["web_change"]]
        if changes:
            yield {**website(capture, section="network_note"), "change": "; ".join(changes)}
