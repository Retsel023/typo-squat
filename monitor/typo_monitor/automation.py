"""Opt-in, authenticated text-only handoff. Screenshots stay in manual UI."""

import hmac
import os
from uuid import UUID

from flask import Blueprint, abort, jsonify, request

from .domains import normalize_domain
from .text_review import review_selection, pack_pair


def create_automation_blueprint(service):
    bp = Blueprint("automation", __name__, url_prefix="/api")
    token = os.environ.get("TYPO_MONITOR_API_TOKEN", "")

    @bp.before_request
    def authenticate():
        if len(token) < 32:
            abort(404, description="Automation API is not configured.")
        supplied = request.headers.get("Authorization", "")
        if not hmac.compare_digest(supplied.encode("utf-8"), ("Bearer " + token).encode("utf-8")):
            abort(401, description="A valid automation Bearer token is required.")

    def require_run(run_id):
        run = service.store.get_run(str(run_id))
        if run is None:
            abort(404, description="Scan not found.")
        return run

    def run_status(run):
        return {key: run.get(key) for key in ("id", "project_id", "status", "started_at", "finished_at", "counts", "error", "discovery_mode", "capture_policy")}

    @bp.get("/projects")
    def projects():
        return {"projects": [{"id": project["id"], "name": project["name"]} for project in service.store.list_projects()]}

    @bp.post("/scans")
    def scans():
        body = request.get_json(silent=True)
        try:
            project_id = str(UUID(body["project_id"]))
        except (KeyError, TypeError, ValueError, AttributeError):
            abort(400, description="Provide a project_id UUID in the JSON body.")
        if service.store.get_project(project_id) is None:
            abort(404, description="Project not found.")
        try:
            mode = body.get("discovery_mode")
            if "discovery_mode" in body and mode is None:
                raise ValueError("discovery_mode must be enumerate or cached when supplied.")
            capture_mode = body.get("capture_mode")
            if "capture_mode" in body and capture_mode is None:
                raise ValueError("capture_mode must be changes or full when supplied.")
            run = service.submit_scan(project_id, discovery_mode=mode, capture_mode=capture_mode)
            return jsonify(run_status(run)), 202
        except RuntimeError as exc:
            abort(409, description=str(exc))
        except ValueError as exc:
            abort(400, description=str(exc))

    @bp.get("/runs/<uuid:run_id>")
    def scan_status(run_id):
        return run_status(require_run(run_id))

    @bp.get("/runs/<uuid:run_id>/text-review")
    @bp.get("/runs/<uuid:run_id>/review")
    def review_manifest(run_id):
        run = require_run(run_id)
        if run["status"] not in {"completed", "partial"}:
            abort(409, description="A completed or partial scan is required.")
        include_images = request.args.get("include_images", "0") == "1"
        if include_images:
            abort(400, description="Image transfer for AI is disabled. Use text-review with include_text=1.")
        include_text = request.args.get("include_text", "0") == "1"
        domain, scheme = request.args.get("domain", ""), request.args.get("scheme", "")
        try:
            if domain:
                domain = normalize_domain(domain)
        except ValueError:
            abort(400, description="Choose a valid candidate domain.")
        if scheme and scheme not in ("http", "https"):
            abort(400, description="Choose HTTP or HTTPS.")
        if include_text and (not domain or not scheme):
            abort(400, description="Text transfer requires one explicit domain and scheme.")
        try:
            limit = int(request.args.get("limit", "100"))
            offset = int(request.args.get("offset", "0"))
            if not 1 <= limit <= 1000 or offset < 0:
                raise ValueError
        except ValueError:
            abort(400, description="Review limit must be 1–1000 and offset nonnegative.")
        selection = review_selection(service.store, str(run_id),
                                     include_parked=request.args.get("include_parked") == "1",
                                     include_reviewed=request.args.get("include_reviewed") == "1")
        captures = [pair for pair in selection["items"]
                    if (not domain or pair["domain"] == domain) and (not scheme or pair["scheme"] == scheme)]
        items = [pack_pair(pair, include_text=include_text) for pair in captures[offset:offset + limit]]
        next_offset = offset + limit if offset + limit < len(captures) else None
        return {"run_id": str(run_id), "items": items, "total": len(captures), "next_offset": next_offset,
                "images_included": False, "text_included": include_text, "summary": selection["summary"],
                "analysis": "Local static text comparison; no AI provider has been called."}

    @bp.post("/runs/<uuid:run_id>/text-reviews")
    @bp.post("/runs/<uuid:run_id>/reviews")
    def save_review(run_id):
        require_run(run_id)
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description="Provide an AI assessment JSON object.")
        try:
            result = service.store.save_capture_review(str(run_id), body.get("domain"), body.get("scheme"), body, text_only=True)
        except (ValueError, TypeError) as exc:
            abort(400, description=str(exc))
        return {"run_id": str(run_id), "domain": result["domain"], "scheme": result["scheme"], "analysis": result["analysis"]}

    @bp.errorhandler(400)
    @bp.errorhandler(401)
    @bp.errorhandler(404)
    @bp.errorhandler(409)
    @bp.errorhandler(413)
    def api_error(error):
        return {"error": error.description}, error.code

    return bp
