"""Parameterized inventory filters applied before counts, paging and exports."""

from functools import lru_cache
import json

from .capture_changes import resolved_change, review_priority, substantial_layout_change
from .capture_images import has_capture_image


OPTIONS = {
    "activity": {"": "All activity", "new": "Newly resolving domains", "dns": "Any DNS change",
        "dns_only": "DNS changed · website unchanged", "records": "DNS records changed",
        "reappeared": "Resolves again", "missing": "DNS absence confirmed",
        "priority": "New / priority website changes", "title": "Website title changed",
        "layout": "Substantial layout / form changes", "context": "Minor / unconfirmed website updates",
        "unchanged": "Website unchanged"},
    "screenshots": {"": "Any screenshot state", "with": "With saved screenshot",
        "without": "Without saved screenshot", "latest": "Screenshot captured in latest scan",
        "failed": "Latest capture failed / unavailable", "skipped": "Latest capture skipped"},
    "website": {"": "Any website check", "responsive": "HTTP response observed",
        "no_response": "No HTTP response", "uncertain": "Website check uncertain",
        "unchecked": "No saved website check", "2xx": "Final HTTP 2xx", "3xx": "Final HTTP 3xx",
        "4xx": "Final HTTP 4xx", "5xx": "Final HTTP 5xx", "complete_text": "Complete saved page text",
        "incomplete_text": "Incomplete / uncertain page text"},
    "protocol": {"": "Either HTTP or HTTPS", "http": "HTTP", "https": "HTTPS", "both": "Both HTTP and HTTPS"},
    "exclusions": {"": "Include title-excluded entries", "hide": "Hide title-excluded entries",
        "only": "Only title-excluded entries"},
    "parking": {"": "Any parking signal", "likely": "Likely parked", "no_signal": "No known parking signal",
        "unassessed": "Parking not assessed"},
    "record_type": {"": "Any DNS record type", **{kind: kind for kind in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")}},
    "sort": {"domain": "Domain A–Z", "domain_desc": "Domain Z–A", "newest": "Newest DNS discoveries first",
        "checked": "Most recent DNS check first"},
}
DEFAULTS = {key: "domain" if key == "sort" else "" for key in OPTIONS}
DEFAULTS["exclude_q"] = ""
ORDER = {"domain": "d.domain", "domain_desc": "d.domain DESC",
         "newest": "d.first_seen IS NULL,d.first_seen DESC,d.domain",
         "checked": "d.last_checked IS NULL,d.last_checked DESC,d.domain"}
LATEST_RUN = """FROM runs r WHERE r.project_id=? AND r.status IN ('completed','partial') AND r.report_deleted=0
    ORDER BY r.started_at DESC,r.rowid DESC LIMIT 1"""


def normalize_options(options):
    if options.keys() - DEFAULTS.keys():
        raise ValueError("Unknown inventory filter.")
    result = {**DEFAULTS, **options}
    for key, choices in OPTIONS.items():
        if not isinstance(result[key], str) or result[key] not in choices:
            raise ValueError(f"Choose a valid {key.replace('_', ' ')} filter.")
    if not isinstance(result["exclude_q"], str) or len(result["exclude_q"]) > 253:
        raise ValueError("Excluded domain/title text must contain at most 253 characters.")
    result["exclude_q"] = result["exclude_q"].strip()
    return result


# Project only comparison metadata into Python; page text, link lists and
# layout profiles are unnecessary for the existing report-priority policy.
_PRIORITY_FIELDS = ("status", "title", "title_status", "title_http_status", "web_change", "content_change",
    "form_change", "structure_comparison", "layout_similarity", "capture_layout_comparison",
    "content_sha256", "previous_content_sha256")
_PRIORITY_JSON = "json_object(" + ",".join(
    f"'{key}',json_extract(c.preflight_json,'$.{key}')" for key in _PRIORITY_FIELDS) + "," + ",".join(
    f"'{known}',CASE WHEN json_type(c.preflight_json,'$.{known}') IS NULL "
    f"THEN json_extract(c.preflight_json,'$.{old}') ELSE json_extract(c.preflight_json,'$.{known}') END"
    for known, old in (("previous_known_title", "previous_title"), ("previous_known_title_status", "previous_title_status"))) \
    + ",'text_diff',length(coalesce(json_extract(c.preflight_json,'$.text_diff'),''))>0)"


@lru_cache(maxsize=1024)
def _activity_match(activity, domain, status, title, http_status, metadata):
    probe = json.loads(metadata)
    if probe.get("status") != "http_response":
        return False
    capture = {"domain": domain, "status": status, "title": title, "http_status": http_status, "preflight": probe}
    priority, _ = review_priority(capture)
    change = resolved_change(capture)
    if activity == "priority":
        return priority in {"new", "major"}
    if activity == "context":
        return priority == "context"
    if activity == "title":
        return change == "title_changed"
    if activity == "layout":
        return probe.get("form_change") == "changed" or substantial_layout_change(probe)
    if activity == "unchanged":
        return change == "unchanged" and priority == "other" and 200 <= (probe.get("title_http_status") or 0) < 300
    return False


def register_functions(db, project_id):
    from .title_filter import combine_policies
    global_row = db.execute("SELECT value_json FROM app_settings WHERE key='capture_filter'").fetchone()
    project_row = db.execute("SELECT capture_filter_json FROM projects WHERE id=?", (project_id,)).fetchone()
    policy = combine_policies(json.loads(global_row[0]) if global_row else {}, json.loads(project_row[0]) if project_row else {})
    rules = tuple(rule.casefold() for rule in policy["rules"])
    db.create_function("inventory_activity", 6, _activity_match, deterministic=True)
    db.create_function("inventory_contains", -1,
        lambda query, *titles: any(query.casefold() in value.casefold() for value in titles if isinstance(value, str)),
        deterministic=True)
    db.create_function("inventory_image", 4,
        lambda run, status, path, scheme: has_capture_image(
            {"run_id": run, "status": status, "relative_path": path, "scheme": scheme}), deterministic=True)
    db.create_function("inventory_title_match", -1,
        lambda *titles: any(rule in title.casefold() for title in titles if isinstance(title, str) for rule in rules),
        deterministic=True)


def conditions(project_id, *, query="", **options):
    options = normalize_options(options)
    clauses, parameters = [], []
    protocol = options["protocol"]
    schemes = (protocol,) if protocol in {"http", "https"} else ("http", "https")

    def latest(field):
        parameters.append(project_id)
        return f"(SELECT {field} {LATEST_RUN})"

    def attempts(predicate, *, current=False, every=False, any_protocol=False):
        ids = ",".join("(SELECT h.rowid FROM captures h WHERE h.project_id=d.project_id AND h.domain=d.domain "
            f"AND h.scheme='{scheme}' ORDER BY h.captured_at DESC,h.rowid DESC LIMIT 1)" for scheme in schemes)
        scope = f"c.run_id={latest('r.id')}" if current else f"c.rowid IN ({ids})"
        scope += " AND c.scheme IN (" + ",".join(f"'{scheme}'" for scheme in schemes) + ")"
        rows = "FROM captures c WHERE c.project_id=d.project_id AND c.domain=d.domain AND " + scope
        if (every or protocol == "both") and not any_protocol:
            return f"(SELECT COUNT(*) {rows} AND ({predicate}))={len(schemes)}"
        return f"EXISTS(SELECT 1 {rows} AND ({predicate}))"

    image_row = """SELECT i.rowid FROM captures i WHERE i.project_id=c.project_id AND i.domain=c.domain
        AND i.scheme=c.scheme AND i.status='captured' ORDER BY i.captured_at DESC,i.rowid DESC LIMIT 1"""
    image_title = f"(SELECT i.title FROM captures i WHERE i.rowid=({image_row}))"
    image_html_title = f"(SELECT json_extract(i.preflight_json,'$.title') FROM captures i WHERE i.rowid=({image_row}))"
    not_excluded = """coalesce(json_extract(c.preflight_json,'$.skip_reason'),'') NOT IN ('title_rule','duplicate_body')
        AND coalesce(json_extract(c.preflight_json,'$.report_exclusion'),'')<>'browser_title_rule'"""
    image = "inventory_image(c.run_id,c.status,c.relative_path,c.scheme)"
    previous_image = f"""EXISTS(SELECT 1 FROM captures i WHERE i.rowid=({image_row})
        AND inventory_image(i.run_id,i.status,i.relative_path,i.scheme)
        AND coalesce(json_extract(i.preflight_json,'$.report_exclusion'),'')<>'browser_title_rule')"""
    image = f"({not_excluded}) AND ({image} OR (c.status<>'captured' AND {previous_image}))"
    visible_image_titles = ",".join(f"CASE WHEN ({image}) THEN {value} ELSE NULL END"
                                    for value in (image_title, image_html_title))
    fallback_title = f"""(SELECT coalesce(nullif(i.title,''),json_extract(i.preflight_json,'$.title'))
        FROM captures i WHERE i.rowid=({image_row}) AND ({image}))"""
    title_match = "inventory_contains(?,c.title,json_extract(c.preflight_json,'$.title')," + visible_image_titles + ")"
    for value, excluded in ((query, False), (options["exclude_q"], True)):
        if not value:
            continue
        # Domain and title searches are literal, including %, _ and quotes.
        literal = value.casefold().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        parameters.extend(("%" + literal + "%", value))
        match = "d.domain LIKE ? ESCAPE '\\' OR " + attempts(title_match)
        clauses.append(("NOT " if excluded else "") + "(" + match + ")")
    if options["screenshots"]:
        image_condition = {"failed": "c.status IN ('failed','unavailable')", "skipped": "c.status='skipped'",
            "latest": f"({not_excluded}) AND inventory_image(c.run_id,c.status,c.relative_path,c.scheme)"}.get(options["screenshots"], image)
        image_match = attempts(image_condition,
            current=options["screenshots"] == "latest", any_protocol=options["screenshots"] == "without")
        clauses.append(("NOT (" + image_match + ")") if options["screenshots"] == "without" else image_match)
    if options["website"]:
        website = options["website"]
        predicate = {"responsive": "json_extract(c.preflight_json,'$.status')='http_response'",
            "no_response": "json_extract(c.preflight_json,'$.status')='no_http_response'",
            "uncertain": "coalesce(json_extract(c.preflight_json,'$.status'),'unknown') NOT IN ('http_response','no_http_response')",
            "complete_text": "json_extract(c.preflight_json,'$.content_status')='complete'",
            "incomplete_text": "json_extract(c.preflight_json,'$.content_status') NOT IN ('complete','disabled')",
            "unchecked": "1"}.get(website)
        if website.endswith("xx"):
            minimum = int(website[0]) * 100
            predicate = f"coalesce(json_extract(c.preflight_json,'$.title_http_status'),c.http_status) BETWEEN {minimum} AND {minimum + 99}"
        check = attempts(predicate, any_protocol=website == "unchecked")
        clauses.append("NOT (" + check + ")" if website == "unchecked" else check)
    elif (protocol and not options["screenshots"] and not options["exclusions"]
            and options["activity"] not in {"priority", "title", "layout", "context", "unchanged", "dns_only"}):
        clauses.append(attempts("1"))
    if options["exclusions"]:
        excluded = """coalesce(json_extract(c.preflight_json,'$.skip_reason'),'')='title_rule'
            OR coalesce(json_extract(c.preflight_json,'$.report_exclusion'),'')='browser_title_rule'
            OR (NOT EXISTS(SELECT 1 FROM inventory s WHERE s.project_id=d.project_id AND s.domain=d.domain AND s.kind='seed')
                AND inventory_title_match(c.title,json_extract(c.preflight_json,'$.title'),CASE
                    WHEN nullif(trim(c.title),'') IS NULL AND nullif(trim(json_extract(c.preflight_json,'$.title')),'') IS NULL
                    THEN """ + fallback_title + " ELSE NULL END))"
        # A match in either protocol excludes the domain; a non-match on its
        # companion must not let it leak back into an exclusions-only search.
        check = attempts(excluded, any_protocol=True)
        clauses.append("NOT (" + check + ")" if options["exclusions"] == "hide" else check)
    activity = options["activity"]
    if activity == "new":
        clauses.append(f"d.first_seen={latest('r.finished_at')}")
    elif activity in {"dns", "dns_only", "records", "reappeared", "missing"}:
        kinds = {"records": ("records_changed",), "reappeared": ("reappeared",), "missing": ("missing_confirmed",)}.get(
            activity, ("newly_observed", "records_changed", "reappeared", "missing_confirmed"))
        clauses.append("d.domain IN (SELECT json_extract(e.value,'$.domain') FROM json_each(" + latest("r.events_json")
            + ") e WHERE json_extract(e.value,'$.kind') IN (" + ",".join(f"'{kind}'" for kind in kinds) + "))")
    if activity in {"priority", "title", "layout", "context", "unchanged", "dns_only"}:
        wanted = "unchanged" if activity == "dns_only" else activity
        predicate = f"inventory_activity('{wanted}',c.domain,c.status,c.title,c.http_status,{_PRIORITY_JSON})"
        predicate += " AND coalesce(json_extract(c.preflight_json,'$.skip_reason'),'')<>'title_rule'"
        predicate += " AND coalesce(json_extract(c.preflight_json,'$.report_exclusion'),'')<>'browser_title_rule'"
        clauses.append(attempts(predicate, current=True, every=activity == "dns_only"))
    if options["parking"]:
        statuses = {"likely": "likely_parked", "no_signal": "not_detected", "unassessed": "unknown"}
        clauses.append("coalesce((SELECT e.parking_status FROM domain_enrichment e WHERE e.project_id=d.project_id "
                       "AND e.domain=d.domain),'unknown')=?")
        parameters.append(statuses[options["parking"]])
    if options["record_type"]:
        clauses.append("EXISTS(SELECT 1 FROM json_each(d.records_json) record WHERE json_extract(record.value,'$[0]')=?)")
        parameters.append(options["record_type"])
    return clauses, parameters
