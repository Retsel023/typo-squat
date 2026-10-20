"""Local, server-rendered interface for persistent domain monitoring."""

from __future__ import annotations

import csv
import io
import math
import os
import secrets
from datetime import datetime
from pathlib import Path
from uuid import UUID

from flask import (
    Flask, Response, abort, flash, g, redirect, render_template, request, send_file, session, url_for,
)

from .domains import normalize_domain, parse_domains
from .text_review import review_selection
from .progress import read_progress, read_tool_output
from .body_groups import group_report_entries


DOMAIN_LABELS = {
    "resolved": "Resolves",
    "pending_missing": "Awaiting confirmation",
    "missing": "DNS absence confirmed",
    "unknown": "DNS uncertain",
}
EVENT_LABELS = {
    "newly_observed": "Newly observed",
    "records_changed": "DNS records changed",
    "missing_confirmed": "DNS absence confirmed",
    "reappeared": "Resolves again",
}
RUN_LABELS = {
    "running": "Scan in progress", "completed": "Completed",
    "partial": "Completed with gaps", "failed": "Failed", "cancelled": "Stopped",
}
PROGRESS_STAGES = {
    "queued": "Waiting to start", "discovery": "Finding subdomains",
    "generation": "Generating typo candidates", "dns": "Checking DNS",
    "pipeline": "Checking DNS and capturing websites",
    "parking": "Checking parking signals", "websites": "Checking website responses",
    "screenshots": "Capturing websites",
    "publishing": "Saving results", "completed": "Completed",
    "partial": "Completed with gaps", "cancelled": "Stopped", "failed": "Failed",
}


def _date(value):
    if not value:
        return "—"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.strftime("%d %b %Y · %H:%M UTC") if parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0 else parsed.strftime("%d %b %Y · %H:%M %z")
    except (ValueError, TypeError):
        return str(value)


def _records(value):
    """Present normalized records and tolerate legacy serialized observations."""
    if not value:
        return []
    if isinstance(value, dict):
        value = value.get("records", [])
    result = []
    for record in value:
        if isinstance(record, dict):
            result.append((record.get("type", ""), record.get("value", "")))
        elif isinstance(record, (list, tuple)) and len(record) >= 2:
            result.append((record[0], record[1]))
        else:
            result.append(("", str(record)))
    return result


def _csv_cell(value):
    text = "" if value is None else str(value)
    # Spreadsheet applications can evaluate formulas even when CSV-quoted.
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def _has_capture_image(capture):
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


def _website_report_groups(captures, mode):
    from .capture_changes import report_entries
    entries = report_entries(captures, mode)
    for entry in entries:
        entry["has_image"] = _has_capture_image(entry["capture"])
    # Keep all observations in the groups so domain lists and detail links do
    # not change when an endpoint has no screenshot. Visibility is separate.
    return entries, group_report_entries(entries)


def _saved_capture(attempt):
    probe = attempt.get("preflight", {}) if isinstance(attempt, dict) else {}
    if probe.get("skip_reason") in {"title_rule", "duplicate_body"} or probe.get("report_exclusion") == "browser_title_rule":
        return None
    if _has_capture_image(attempt):
        return attempt
    previous = attempt.get("previous_capture") if isinstance(attempt, dict) else None
    if previous and previous.get("preflight", {}).get("report_exclusion") == "browser_title_rule":
        return None
    if (_has_capture_image(previous) and previous.get("domain") == attempt.get("domain")
            and previous.get("scheme") == attempt.get("scheme") and previous.get("project_id") == attempt.get("project_id")):
        return previous
    return None


def _capture_status(attempt):
    if not attempt:
        return "No screenshot"
    error = str(attempt.get("error") or "").strip().lower()
    if (attempt.get("preflight") or {}).get("report_exclusion") == "browser_title_rule":
        return "Excluded after browser title check"
    if (attempt.get("preflight") or {}).get("skip_reason") == "duplicate_body":
        source = (attempt.get("preflight") or {}).get("duplicate_body_of", "other protocol")
        return f"HTML matches {source.upper()} · duplicate capture skipped"
    if (attempt.get("preflight") or {}).get("skip_reason") == "unchanged_content":
        return "Text unchanged · capture skipped"
    if (attempt.get("preflight") or {}).get("skip_reason") == "unchanged_title":
        return "Title unchanged · no capture requested"
    if error.startswith("screenshot excluded by title rule:"):
        return "Excluded by title rule"
    timed_out = "timed out" in error or "timeout" in error or "deadline" in error
    if error.startswith("website check"):
        return "Website check timed out" if timed_out else "Website check uncertain"
    if "no http response" in error:
        return "No HTTP response"
    if timed_out:
        return "Capture timed out"
    return "Screenshot unavailable"


def _prepare_domain(domain):
    """Show recorded images, retaining old evidence and compact failed checks."""
    result = dict(domain)
    attempts = {item.get("scheme"): item for item in result.get("screenshots", [])
                if isinstance(item, dict) and item.get("scheme") in {"http", "https"}}
    image_schemes = [scheme for scheme in ("http", "https") if _saved_capture(attempts.get(scheme))]
    result.update(image_schemes=image_schemes, gallery_schemes=list(image_schemes),
                  unavailable_schemes=[scheme for scheme in ("http", "https") if scheme not in image_schemes])
    return result


def create_app(service):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=secrets.token_hex(32), MAX_CONTENT_LENGTH=64 * 1024,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
    app.extensions["monitor_service"] = service
    app.jinja_env.filters["date"] = _date
    app.jinja_env.filters["records"] = _records
    app.jinja_env.filters["saved_capture"] = _saved_capture
    app.jinja_env.filters["capture_status"] = _capture_status
    app.jinja_env.filters["has_image"] = _has_capture_image

    @app.before_request
    def protect_forms():
        # This Blueprint authenticates its own requests with a bearer token.
        if request.blueprint == "automation":
            return
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        if request.method == "POST":
            supplied = request.form.get("csrf_token", "")
            if not secrets.compare_digest(supplied, session["csrf_token"]):
                abort(400, description="This form expired. Reload the page and try again.")

    @app.after_request
    def response_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
        response.headers["Cache-Control"] = ("private, max-age=31536000, immutable"
                                             if request.endpoint == "capture_image" and response.status_code == 200
                                             else "no-store")
        return response

    def navigation_projects():
        if "navigation_projects" not in g:
            g.navigation_projects = service.store.list_projects()
        return g.navigation_projects

    def default_dns_workers():
        workers = getattr(service, "dns_workers", None)
        return workers if workers is not None else (getattr(getattr(service, "resolver", None), "workers", 24) or 24)

    def parse_dns_workers(value):
        value = value.strip()
        if not value:
            return None
        if not value.isascii() or not value.isdigit() or len(value) > 3 or not 1 <= int(value) <= 128:
            raise ValueError("DNS concurrency must be a whole number from 1 to 128, or blank for the server default.")
        return int(value)

    @app.context_processor
    def common_context():
        from .capture_changes import PERFORMANCE_DEFAULTS
        return {"csrf_token": session.get("csrf_token", ""), "domain_labels": DOMAIN_LABELS,
                "event_labels": EVENT_LABELS, "run_labels": RUN_LABELS,
                "interval_hours": getattr(service, "interval_hours", 0),
                "server_dns_workers": default_dns_workers(),
                "capture_defaults": getattr(service, "capture_defaults", PERFORMANCE_DEFAULTS),
                "navigation_projects": navigation_projects()}

    def project_or_404(project_id):
        try:
            project = service.store.get_project(str(project_id))
        except KeyError:
            project = None
        if project is None:
            abort(404, description="This project could not be found.")
        return project

    def live_data(run_id):
        data_dir = getattr(service, "data_dir", None)
        return read_progress(data_dir, str(run_id)), read_tool_output(data_dir, str(run_id))

    def selected_filters():
        status = request.args.get("status", "resolved")
        if status and status not in DOMAIN_LABELS:
            abort(400, description="Choose a valid domain status.")
        seed = request.args.get("seed", "").strip()
        if seed and seed != "__unattributed__":
            try:
                seed = normalize_domain(seed)
            except ValueError:
                abort(400, description="Choose a valid source domain.")
        return {"query": request.args.get("q", "").strip()[:253], "status": status,
                "seed": seed, "hide_parked": request.args.get("hide_parked", "") == "1",
                "include_seeds": request.args.get("include_seeds", "") == "1"}

    def selected_view():
        view = request.args.get("view", "gallery")
        if view not in {"gallery", "table"}:
            abort(400, description="Choose gallery or table view.")
        return view

    def filter_parameters(filters, view):
        return {"status": filters["status"], "q": filters["query"], "view": view,
                "hide_parked": "1" if filters["hide_parked"] else "0",
                "include_seeds": "1" if filters["include_seeds"] else "0"}

    @app.get("/")
    def dashboard():
        projects = []
        all_counts = {"total": 0, **{status: 0 for status in DOMAIN_LABELS}}
        for item in navigation_projects():
            project = dict(item)
            project["counts"] = service.store.domain_counts(project["id"])
            for key in all_counts:
                all_counts[key] += project["counts"].get(key, 0)
            projects.append(project)
        tools = service.tool_status()
        return render_template("dashboard.html", projects=projects, counts=all_counts,
                               tools=tools, form={}, page="overview")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/projects/new")
    def new_project():
        return render_template("create.html", form={}, page="new")

    @app.post("/projects")
    def create_project():
        name = request.form.get("name", "").strip()
        roots_text = request.form.get("roots", "")
        workers_text = request.form.get("dns_workers", "")
        try:
            if not name or len(name) > 120:
                raise ValueError("Give your project a name between 1 and 120 characters.")
            roots = parse_domains(roots_text)
            if not roots:
                raise ValueError("Add at least one root domain.")
            if len(roots) > 500:
                raise ValueError("Add no more than 500 root domains to one project.")
            dns_workers = parse_dns_workers(workers_text)
            project = service.create_project(name, roots, dns_workers=dns_workers)
        except ValueError as error:
            flash(str(error), "error")
            # Keep submitted values without embedding them in a redirect URL.
            return render_template("create.html", form={"name": name, "roots": roots_text, "dns_workers": workers_text}, page="new"), 400
        flash("Project created. Start a scan to establish its first baseline.", "success")
        return redirect(url_for("project_detail", project_id=project["id"]), code=303)

    @app.get("/projects/<uuid:project_id>")
    def project_detail(project_id):
        project = project_or_404(project_id)
        counts = service.store.domain_counts(str(project_id))
        filters = selected_filters()
        view = selected_view()
        query, status, seed = filters["query"], filters["status"], filters["seed"]
        include_seeds, hide_parked = filters["include_seeds"], filters["hide_parked"]
        page_text = request.args.get("page", "1")
        if not page_text.isascii() or not page_text.isdigit() or len(page_text) > 8:
            abort(400, description="Choose a valid inventory page number.")
        page_number = max(1, int(page_text))
        page_size = 100
        result = service.store.query_domains(str(project_id), **filters,
                                             limit=page_size, offset=(page_number - 1) * page_size)
        page_count = max(1, (result["total"] + page_size - 1) // page_size)
        if page_number > page_count:
            page_number = page_count
            result = service.store.query_domains(str(project_id), **filters,
                                                 limit=page_size, offset=(page_number - 1) * page_size)
        groups = service.store.source_groups(str(project_id), query=query, status=status,
                                             hide_parked=hide_parked, include_seeds=include_seeds)
        # Roots act as section labels; related discovered subdomains stay beside them.
        source_sections = [{"root": root, "groups": []} for root in project["roots"]]
        other_sources = []
        for group in groups:
            matches = [section for section in source_sections
                       if group["seed"] == section["root"] or group["seed"].endswith("." + section["root"])]
            if matches:
                max(matches, key=lambda section: len(section["root"]))["groups"].append(group)
            else:
                other_sources.append(group)
        source_sections = [section for section in source_sections if section["groups"]]
        if other_sources:
            source_sections.append({"root": "Other sources", "groups": other_sources})
        for section in source_sections:
            section["groups"].sort(key=lambda group: (group["seed"] != section["root"], group["seed"]))
        source_total = (service.store.query_domains(str(project_id), **{**filters, "seed": ""}, limit=1)["total"]
                        if seed else result["total"])
        default_count = service.store.query_domains(str(project_id), status="resolved", include_seeds=False, limit=1)["total"]
        filter_params = filter_parameters(filters, view)
        history_text = request.args.get("history_page", "1")
        if not history_text.isascii() or not history_text.isdigit() or len(history_text) > 8 or int(history_text) < 1:
            abort(400, description="Choose a valid scan history page number.")
        history_page = int(history_text)
        history_rows = service.store.list_runs(str(project_id), limit=21, include_events=False,
                                              offset=(history_page - 1) * 20)
        runs = history_rows[:20]
        last_run = project.get("last_run") or (runs[0] if runs else None)
        if hasattr(service, "schedule_status"):
            schedule = service.schedule_status(project)
        else:
            inherited = project.get("schedule_interval_hours") is None
            schedule = {"interval_hours": getattr(service, "interval_hours", 0) if inherited else project["schedule_interval_hours"],
                        "next_run_at": project.get("schedule_next_run_at"), "inherited": inherited}
        if hasattr(service, "dns_status"):
            dns_settings = service.dns_status(project)
        else:
            inherited = project.get("dns_workers") is None
            dns_settings = {"workers": default_dns_workers() if inherited else project["dns_workers"], "inherited": inherited}
        discovery_settings = (service.discovery_status(project) if hasattr(service, "discovery_status") else
            {"mode": project.get("discovery_mode", "enumerate"), "cached_available": bool(counts["total"]),
             "enumeration_enabled": getattr(service, "discovery", True)})
        from .proxy import public_settings, tor_proxy_url
        proxy_settings = public_settings(service.store.proxy_settings(str(project_id)))
        return render_template("project.html", project=project, domains=[_prepare_domain(item) for item in result["items"]],
                               counts=counts, query=query, status_filter=status,
                               runs=runs, last_run=last_run, page="project", history_page=history_page,
                               history_has_more=len(history_rows) > 20,
                               demo=bool(last_run and "demo" in last_run.get("source_status", {})),
                               page_number=page_number, page_count=page_count,
                               filtered_count=result["total"], offset=(page_number - 1) * page_size,
                               include_seeds=include_seeds, hide_parked=hide_parked,
                               seed_filter=seed, source_sections=source_sections,
                               source_group_count=len(groups), source_total=source_total,
                               default_count=default_count, hidden_count=counts["total"] - default_count,
                               filter_params=filter_params, view=view, schedule=schedule, dns_settings=dns_settings,
                               discovery_settings=discovery_settings,
                               global_capture_filter=service.store.global_capture_filter(),
                               proxy_settings=proxy_settings,
                               tor_proxy_endpoint=tor_proxy_url(),
                               gallery_params={**filter_params, "view": "gallery"},
                               table_params={**filter_params, "view": "table"},
                               has_custom_filters=bool(query or seed or hide_parked or include_seeds or status != "resolved"))

    @app.get("/projects/<uuid:project_id>/candidates/<domain>")
    def candidate_detail(project_id, domain):
        project = project_or_404(project_id)
        try:
            domain = normalize_domain(domain)
        except ValueError:
            abort(404, description="This candidate could not be found.")
        candidate = service.store.get_domain(str(project_id), domain)
        if candidate is None:
            abort(404, description="This candidate could not be found in this project.")
        filters, view = selected_filters(), selected_view()
        references = []
        for source in candidate.get("sources", [])[:6]:
            if source == domain:
                continue
            try:
                reference = service.store.get_domain(str(project_id), normalize_domain(source))
            except ValueError:
                continue
            if reference:
                references.append(_prepare_domain(reference))
        candidate = _prepare_domain(candidate)
        comparisons = []
        assessments = []
        for capture in candidate.get("screenshots", []):
            if not isinstance(capture, dict):
                continue
            analysis = capture.get("analysis")
            if isinstance(analysis, dict) and analysis:
                assessments.append({"scheme": capture.get("scheme", ""), "analysis": analysis,
                                    "captured_at": capture.get("captured_at")})
            if not _has_capture_image(capture) or _saved_capture(capture) is None:
                continue
            previous = service.store.previous_successful_capture(capture["run_id"], domain, capture["scheme"])
            if _has_capture_image(previous):
                comparisons.append({"scheme": capture["scheme"], "before": previous, "after": capture})
        return render_template("candidate.html", project=project, candidate=candidate,
                               captures=service.store.list_captures(str(project_id), domain, limit=20),
                               references=references, comparisons=comparisons, assessments=assessments,
                               last_run=project.get("last_run"), filter_params=filter_parameters(filters, view),
                               seed_filter=filters["seed"], page="candidate",
                               demo=bool(project.get("last_run") and "demo" in project["last_run"].get("source_status", {})))

    @app.get("/captures/<uuid:run_id>/<domain>/<scheme>")
    def capture_image(run_id, domain, scheme):
        if scheme not in {"http", "https"}:
            abort(404)
        try:
            domain = normalize_domain(domain)
        except ValueError:
            abort(404)
        capture = service.store.get_capture(str(run_id), domain, scheme)
        run = service.store.get_run(str(run_id))
        if (not capture or not run or capture.get("status") != "captured"
                or capture.get("run_id") != str(run_id) or capture.get("domain") != domain
                or capture.get("scheme") != scheme or capture.get("project_id") != run["project_id"]):
            abort(404, description="This capture could not be found.")
        relative = capture.get("relative_path")
        if not isinstance(relative, str) or not relative or "\\" in relative:
            abort(404)
        relative_path = Path(relative)
        if relative_path.is_absolute() or any(part in {".", ".."} for part in relative_path.parts):
            abort(404)
        suffix = relative_path.suffix.lower()
        if suffix not in {".png", ".jpg", ".jpeg"}:
            abort(404)
        stream = None
        try:
            runs_dir = Path(service.data_dir).resolve() / "runs"
            run_dir = runs_dir / str(run_id)
            if runs_dir.is_symlink() or run_dir.is_symlink():
                abort(404)
            capture_path = run_dir
            for part in relative_path.parts:
                capture_path /= part
                if capture_path.is_symlink():
                    abort(404)
            resolved = capture_path.resolve(strict=True)
            if not resolved.is_relative_to(run_dir.resolve(strict=True)) or not resolved.is_file():
                abort(404)
            descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            stream = os.fdopen(descriptor, "rb")
            signature = stream.read(12)
            png = suffix == ".png" and signature.startswith(b"\x89PNG\r\n\x1a\n")
            jpeg = suffix in {".jpg", ".jpeg"} and signature.startswith(b"\xff\xd8\xff")
            if not (png or jpeg):
                stream.close()
                abort(404, description="This capture is not a supported image.")
            stream.seek(0)
            response = send_file(stream, mimetype="image/png" if png else "image/jpeg",
                                 download_name=f"{domain}-{scheme}{suffix}", etag=False)
            response.call_on_close(stream.close)
            return response
        except (OSError, RuntimeError, ValueError):
            if stream is not None:
                stream.close()
            abort(404, description="The saved capture file is unavailable.")

    @app.post("/projects/<uuid:project_id>/scan")
    def scan_project(project_id):
        project_or_404(project_id)
        try:
            mode = request.form.get("discovery_mode")
            run = service.submit_scan(str(project_id), discovery_mode=mode,
                                      capture_mode=request.form.get("capture_mode"))
        except RuntimeError as error:
            abort(409, description=str(error))
        except ValueError as error:
            abort(400, description=str(error))
        return redirect(url_for("run_detail", run_id=run["id"]), code=303)

    @app.post("/projects/<uuid:project_id>/schedule")
    def update_schedule(project_id):
        project = project_or_404(project_id)
        if project.get("last_run") and "demo" in project["last_run"].get("source_status", {}):
            abort(409, description="Simulated demo projects cannot be scheduled. Create a separate project for real scans.")
        if "enumerate_hours" in request.form or "cached_hours" in request.form:
            try:
                intervals = ({"enumerate": 0, "cached": 0} if request.form.get("action") == "off" else
                    {mode: float(request.form.get(mode + "_hours", "")) for mode in ("enumerate", "cached")})
                service.set_schedules(str(project_id), intervals,
                                      discovery_mode=request.form.get("discovery_mode", "enumerate"),
                                      capture_modes={mode: request.form.get(mode + "_capture_mode", "changes")
                                                     for mode in ("enumerate", "cached")})
            except (ValueError, OverflowError) as error:
                abort(400, description=str(error) or "Choose valid intervals for both schedules.")
            flash("Both scan schedules are off." if not any(intervals.values()) else "Independent scan schedules saved.", "success")
            return redirect(url_for("project_detail", project_id=project_id, _anchor="schedule"), code=303)
        try:
            hours = 0.0 if request.form.get("action") == "off" else float(request.form.get("interval_hours", ""))
            if not math.isfinite(hours) or not (hours == 0 or 1 <= hours <= 8760):
                raise ValueError
        except (ValueError, OverflowError):
            abort(400, description="Choose 0 to turn scheduling off, or an interval between 1 and 8760 hours.")
        try:
            mode = request.form.get("discovery_mode")
            if mode is None:
                service.store.set_schedule(str(project_id), hours)
            else:
                service.store.set_schedule(str(project_id), hours, discovery_mode=mode)
        except ValueError as error:
            abort(400, description=str(error))
        flash("Automatic scans are off for this project." if hours == 0 else "Scan schedule saved for this project.", "success")
        return redirect(url_for("project_detail", project_id=project_id, _anchor="schedule"), code=303)

    @app.post("/projects/<uuid:project_id>/dns-settings")
    def update_dns_settings(project_id):
        project = project_or_404(project_id)
        if project.get("last_run") and "demo" in project["last_run"].get("source_status", {}):
            abort(409, description="Simulated demo projects are read only. Create a separate project for real scans.")
        try:
            workers = parse_dns_workers("" if request.form.get("action") == "inherit" else request.form.get("dns_workers", ""))
            service.store.set_dns_workers(str(project_id), workers)
        except ValueError as error:
            abort(400, description=str(error))
        flash("DNS settings saved for future scans in this project.", "success")
        return redirect(url_for("project_detail", project_id=project_id, _anchor="dns-settings"), code=303)

    @app.post("/projects/<uuid:project_id>/name")
    def rename_project(project_id):
        project_or_404(project_id)
        try:
            service.store.rename_project(str(project_id), request.form.get("name", ""))
        except ValueError as error:
            abort(400, description=str(error))
        flash("Project name updated.", "success")
        return redirect(url_for("project_detail", project_id=project_id, _anchor="manage-project"), code=303)

    @app.post("/projects/<uuid:project_id>/proxies")
    def update_proxies(project_id):
        project = project_or_404(project_id)
        if project.get("last_run") and "demo" in project["last_run"].get("source_status", {}):
            abort(409, description="Create a real project to configure proxy routes.")
        from .proxy import STAGES
        changes = {stage: {"enabled": request.form.get(stage + "_enabled") == "1",
                           "source": request.form.get(stage + "_source", "custom"),
                           "url": request.form.get(stage + "_url", ""),
                           "clear": request.form.get(stage + "_clear") == "1"} for stage in STAGES}
        try:
            service.set_proxy_settings(str(project_id), changes)
        except ValueError as error:
            # Validation messages are fixed text and never echo supplied URLs.
            abort(400, description=str(error))
        flash("Proxy settings saved for future scans. Queued and running scans keep their original routes.", "success")
        return redirect(url_for("project_detail", project_id=project_id, _anchor="proxy-settings"), code=303)

    @app.get("/settings/title-exclusions")
    def global_exclusions():
        return render_template("global_exclusions.html", page="global-exclusions",
                               policy=service.store.global_capture_filter())

    @app.post("/projects/<uuid:project_id>/capture-policy")
    def update_capture_policy(project_id):
        project = project_or_404(project_id)
        if project.get("last_run") and "demo" in project["last_run"].get("source_status", {}):
            abort(409, description="Create a real project to configure capture settings.")
        try:
            days = request.form.get("refresh_days", "")
            if not days.isascii() or not days.isdigit() or len(days) > 3:
                raise ValueError("Choose 0–365 days for screenshot refresh.")
            from .capture_changes import PERFORMANCE_LIMITS
            performance = {}
            for key in PERFORMANCE_LIMITS:
                value = request.form.get(key, "").strip()
                if value and (not value.isascii() or not value.isdigit() or len(value) > 3):
                    raise ValueError("Capture performance settings must be whole numbers, or blank for the server default.")
                performance[key] = int(value) if value else None
            service.set_capture_policy(str(project_id), mode=request.form.get("mode", "changes"), refresh_days=int(days), comparison=request.form.get("comparison", "text"), **performance)
        except ValueError as error:
            abort(400, description=str(error))
        flash("Screenshot policy saved for newly queued scans.", "success")
        return redirect(url_for("project_detail", project_id=project_id, _anchor="capture-policy"), code=303)

    @app.post("/settings/title-exclusions")
    def update_global_exclusions():
        try:
            service.set_global_capture_filter(enabled=request.form.get("enabled") == "1",
                rules=[line.strip() for line in request.form.get("rules", "").splitlines() if line.strip()])
        except ValueError as error:
            abort(400, description=str(error))
        flash("Global title exclusions saved for future scans in all projects. Queued and running scans keep their saved rules.", "success")
        return redirect(url_for("global_exclusions"), code=303)

    @app.post("/projects/<uuid:project_id>/capture-filter")
    def update_capture_filter(project_id):
        project = project_or_404(project_id)
        if project.get("last_run") and "demo" in project["last_run"].get("source_status", {}):
            abort(409, description="Create a real project to configure capture filters.")
        try:
            service.set_capture_filter(str(project_id), enabled=request.form.get("enabled") == "1",
                rules=[line.strip() for line in request.form.get("rules", "").splitlines() if line.strip()])
        except ValueError as error:
            abort(400, description=str(error))
        flash("Title exclusions saved for future scans. Domains will still be checked on every run.", "success")
        return redirect(url_for("project_detail", project_id=project_id, _anchor="capture-filter"), code=303)

    def finish_deletion(pending):
        if pending:
            flash("Some deleted files could not be removed yet. Cleanup is saved for retry on server restart; see server logs.", "info")

    @app.route("/projects/<uuid:project_id>/delete", methods=["GET", "POST"])
    def delete_project(project_id):
        project = project_or_404(project_id)
        blocker = service.deletion_blocker(str(project_id))
        code = 200
        if request.method == "POST":
            if request.form.get("confirmation") != "DELETE":
                abort(400, description="Type DELETE to confirm removal.")
            try:
                pending = service.delete_project(str(project_id))
            except KeyError:
                abort(404, description="This project could not be found.")
            except RuntimeError as error:
                blocker, code = str(error), 409
            else:
                flash("Project deleted, including its saved reports and schedule.", "success")
                finish_deletion(pending)
                return redirect(url_for("dashboard"), code=303)
        return render_template("delete.html", project=project, report=None, blocker=blocker, page="project"), code

    @app.route("/runs/<uuid:run_id>/delete", methods=["GET", "POST"])
    def delete_report(run_id):
        report = service.store.get_run(str(run_id))
        if report is None:
            abort(404, description="This scan report could not be found.")
        project = project_or_404(report["project_id"])
        blocker = service.deletion_blocker(project["id"])
        code = 200
        if request.method == "POST":
            if request.form.get("confirmation") != "DELETE":
                abort(400, description="Type DELETE to confirm removal.")
            try:
                project_id, pending = service.delete_report(str(run_id))
            except KeyError:
                abort(404, description="This scan report could not be found.")
            except RuntimeError as error:
                blocker, code = str(error), 409
            else:
                flash("Scan report deleted. The project's saved inventory and DNS state were kept.", "success")
                finish_deletion(pending)
                return redirect(url_for("project_detail", project_id=project_id, _anchor="history"), code=303)
        return render_template("delete.html", project=project, report=report, blocker=blocker, page="project"), code

    @app.post("/runs/<uuid:run_id>/cancel")
    def cancel_scan(run_id):
        if service.store.get_run(str(run_id)) is None:
            abort(404, description="This scan could not be found.")
        try:
            run = service.cancel_scan(str(run_id))
        except KeyError:
            abort(404, description="This scan could not be found.")
        except RuntimeError as error:
            abort(409, description=str(error))
        except ValueError as error:
            abort(400, description=str(error))
        if run["status"] == "running":
            flash("Stop requested. The scan is shutting down; previously accepted findings are preserved.", "info")
        elif run["status"] == "cancelled":
            flash("Scan stopped. Previous results were kept.", "info")
        else:
            flash("This scan has already finished.", "info")
        return redirect(url_for("run_detail", run_id=run_id), code=303)

    @app.get("/runs/<uuid:run_id>")
    def run_detail(run_id):
        try:
            run = service.store.get_run(str(run_id))
        except KeyError:
            run = None
        if run is None:
            abort(404, description="This scan could not be found.")
        project = project_or_404(run["project_id"])
        progress, outputs = live_data(run_id)
        from .capture_changes import website_check_diagnostics, website_network_notes
        report_mode = run.get("capture_policy", {}).get("mode", "full")
        captures = service.store.list_run_captures(str(run_id))
        entries, website_groups = _website_report_groups(captures, report_mode)
        website_groups = [group for group in website_groups if group["has_image"]]
        capture_diagnostics = sorted((entry for entry in entries if not entry["has_image"]),
                                     key=lambda entry: (entry["capture"]["domain"], entry["capture"]["scheme"]))
        body_view = request.args.get("body_view", "all")
        if body_view not in {"all", "shared", "individual"}:
            abort(400, description="Choose all, shared or individual website bodies.")
        body_counts = {"all": len(website_groups), "shared": sum(group["shared"] for group in website_groups)}
        body_counts["individual"] = body_counts["all"] - body_counts["shared"]
        website_entries = [group for group in website_groups if body_view == "all"
                           or group["shared"] == (body_view == "shared")]
        web_endpoint_total = sum(group["endpoint_count"] for group in website_entries)
        web_diagnostics = website_check_diagnostics(captures)
        network_notes = website_network_notes(captures)
        page_text = request.args.get("web_page", "1")
        if not page_text.isascii() or not page_text.isdigit() or len(page_text) > 8 or int(page_text) < 1:
            abort(400, description="Choose a valid website report page.")
        web_pages = max(1, (len(website_entries) + 99) // 100)
        web_page = min(int(page_text), web_pages)
        web_total = len(website_entries)
        website_entries = website_entries[(web_page - 1) * 100:web_page * 100]
        capture_page_text = request.args.get("capture_page", "1")
        if (not capture_page_text.isascii() or not capture_page_text.isdigit()
                or len(capture_page_text) > 8 or int(capture_page_text) < 1):
            abort(400, description="Choose a valid screenshot diagnostics page.")
        capture_total = len(capture_diagnostics)
        capture_pages = max(1, (capture_total + 99) // 100)
        capture_page = min(int(capture_page_text), capture_pages)
        capture_diagnostics = capture_diagnostics[(capture_page - 1) * 100:capture_page * 100]
        handoff = review_selection(service.store, str(run_id)) if run["status"] in {"completed", "partial"} else None
        return render_template("run.html", project=project, run=run, page="run",
                               progress=progress, outputs=outputs, progress_stages=PROGRESS_STAGES,
                               demo="demo" in run.get("source_status", {}), handoff=handoff,
                               website_entries=website_entries, report_mode=report_mode,
                               body_view=body_view, body_counts=body_counts, web_endpoint_total=web_endpoint_total,
                               web_diagnostics=web_diagnostics, network_notes=network_notes,
                               capture_diagnostics=capture_diagnostics, capture_total=capture_total,
                               capture_page=capture_page, capture_pages=capture_pages,
                               capture_log_open="capture_page" in request.args,
                               web_page=web_page, web_pages=web_pages, web_total=web_total,
                               handoff_labels={"original": "Original websites", "failed": "Failed / unavailable captures",
                                               "title_filtered": "Excluded by title rule",
                                               "title_unchanged": "Unchanged titles · no screenshots requested",
                                               "unchanged": "Unchanged text", "uncertain": "Incomplete / uncertain text",
                                               "duplicate": "Duplicate protocol pairs", "parked": "Likely parked",
                                               "reviewed": "Already reviewed"})

    @app.get("/runs/<uuid:run_id>/bodies/<group_id>")
    def body_group_detail(run_id, group_id):
        if len(group_id) != 64 or any(character not in "0123456789abcdef" for character in group_id):
            abort(404, description="This body group could not be found.")
        run = service.store.get_run(str(run_id))
        if run is None:
            abort(404, description="This scan could not be found.")
        project = project_or_404(run["project_id"])
        mode = run.get("capture_policy", {}).get("mode", "full")
        _, groups = _website_report_groups(service.store.list_run_captures(str(run_id)), mode)
        group = next((item for item in groups if item["group_id"] == group_id), None)
        if group is None:
            # Keep each protocol's original content group and saved links accessible.
            group = next((view for item in groups for view in item.get("protocol_views", [])
                          if view["group_id"] == group_id), None)
        if group is None or not (group["complete_body"]
                                 or group["match_kind"] == "protocol_pair" and group["shared"]):
            abort(404, description="This body group is not in this scan's report.")
        page_text = request.args.get("member_page", "1")
        if not page_text.isascii() or not page_text.isdigit() or len(page_text) > 8 or int(page_text) < 1:
            abort(400, description="Choose a valid body group page.")
        member_pages = max(1, (group["member_count"] + 99) // 100)
        member_page = min(int(page_text), member_pages)
        members = group["members"][(member_page - 1) * 100:member_page * 100]
        return render_template("body_group.html", run=run, project=project, page="run", group=group,
                               members=members, member_page=member_page, member_pages=member_pages)

    @app.get("/runs/<uuid:run_id>/progress")
    def run_progress(run_id):
        try:
            run = service.store.get_run(str(run_id))
        except KeyError:
            run = None
        if run is None:
            return {"error": "This scan could not be found."}, 404
        try:
            project = service.store.get_project(str(UUID(run.get("project_id", ""))))
        except (KeyError, TypeError, ValueError, AttributeError):
            project = None
        if project is None:
            return {"error": "This scan could not be found."}, 404
        progress, outputs = live_data(run_id)
        return {"run_id": str(run_id), "status": run["status"], "progress": progress, "outputs": outputs}

    @app.get("/projects/<uuid:project_id>/export.csv")
    def export_project(project_id):
        project_or_404(project_id)
        filters = selected_filters()
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["domain", "status", "latest_observation", "last_known_records", "first_seen", "last_seen", "last_checked", "missing_count", "last_error", "source_domains", "is_original", "parking_status", "parking_provider", "parking_evidence"])
        for domain in service.store.export_domains(str(project_id), **filters):
            record_text = "; ".join(f"{kind} {value}".strip() for kind, value in _records(domain.get("records")))
            parking = domain.get("parking") or {}
            evidence = parking.get("evidence", "")
            if isinstance(evidence, list):
                evidence = "; ".join(map(str, evidence))
            values = [domain.get("domain"), domain.get("status"), domain.get("latest_observation"), record_text,
                      domain.get("first_seen"), domain.get("last_seen"), domain.get("last_checked"),
                      domain.get("missing_count", 0), domain.get("last_error"),
                      "; ".join(domain.get("sources", [])), domain.get("is_seed", False),
                      parking.get("status", "unknown"), parking.get("provider"), evidence]
            writer.writerow([_csv_cell(value) for value in values])
        return Response(output.getvalue(), mimetype="text/csv", headers={
            "Content-Disposition": f'attachment; filename="domain-findings-{project_id}.csv"',
        })

    for error_code in (400, 404, 409, 413):
        def handle_error(error):
            messages = {400: "Check your request", 404: "Page not found", 409: "Action unavailable", 413: "The form is too large"}
            return render_template("error.html", title=messages[error.code],
                                   message=error.description, code=error.code, page="error"), error.code
        app.register_error_handler(error_code, handle_error)

    from .automation import create_automation_blueprint
    app.register_blueprint(create_automation_blueprint(service))
    return app
