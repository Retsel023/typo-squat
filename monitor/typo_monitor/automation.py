"""Opt-in authenticated HTTP interface for n8n Cloud and other schedulers.

No image upload or AI request is made by this application. Image bytes are only
returned for an explicitly requested, authenticated capture pair.
"""

import hmac
import os
from uuid import UUID

from flask import Blueprint, abort, jsonify, request, url_for
from PIL import Image

from .domains import normalize_domain
from .handoff import review_selection
from .handoff_images import image_payload


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
        return {key: run.get(key) for key in ("id", "project_id", "status", "started_at", "finished_at", "counts", "error")}

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
            return jsonify(run_status(service.submit_scan(project_id))), 202
        except RuntimeError as exc:
            abort(409, description=str(exc))
        except ValueError as exc:
            abort(400, description=str(exc))

    @bp.get("/runs/<uuid:run_id>")
    def scan_status(run_id):
        return run_status(require_run(run_id))

    def pack_capture(capture, include_images):
        if capture is None:
            return None
        result = {key: capture.get(key) for key in ("run_id", "domain", "scheme", "url", "status", "title", "http_status", "captured_at", "visual", "analysis")}
        result["visual"] = {key: capture.get("visual", {}).get(key) for key in ("change", "previous_run_id", "duplicate_kind", "duplicate_of", "pixel_sha256")}
        result["image_url"] = url_for("capture_image", run_id=capture["run_id"], domain=capture["domain"], scheme=capture["scheme"])
        if include_images:
            try:
                result.update(image_payload(service.data_dir, capture))
            except (OSError, ValueError, Image.DecompressionBombError):
                result["image_error"] = "The recorded image is unavailable or failed validation."
        return result

    @bp.get("/runs/<uuid:run_id>/review")
    def review_manifest(run_id):
        run = require_run(run_id)
        if run["status"] == "running":
            abort(409, description="The scan is still running.")
        include_images = request.args.get("include_images", "0") == "1"
        domain, scheme = request.args.get("domain", ""), request.args.get("scheme", "")
        try:
            if domain:
                domain = normalize_domain(domain)
        except ValueError:
            abort(400, description="Choose a valid candidate domain.")
        if scheme and scheme not in ("http", "https"):
            abort(400, description="Choose HTTP or HTTPS.")
        if include_images and (not domain or not scheme):
            abort(400, description="Image transfer requires one explicit domain and scheme.")
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
        items = []
        for pair in captures[offset:offset + limit]:
            items.append({"domain": pair["domain"], "scheme": pair["scheme"], "visual_status": pair["visual_status"],
                          "current": pack_capture(pair["current"], include_images), "previous": pack_capture(pair["previous"], include_images),
                          "references": [pack_capture(reference, include_images) for reference in pair["references"]]})
        next_offset = offset + limit if offset + limit < len(captures) else None
        return {"run_id": str(run_id), "items": items, "total": len(captures), "next_offset": next_offset,
                "images_included": include_images, "summary": selection["summary"],
                "analysis": "Local pixel comparison; no AI provider has been called."}

    @bp.post("/runs/<uuid:run_id>/reviews")
    def save_review(run_id):
        require_run(run_id)
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description="Provide an AI assessment JSON object.")
        try:
            result = service.store.save_capture_review(str(run_id), body.get("domain"), body.get("scheme"), body)
        except (ValueError, TypeError) as exc:
            abort(400, description=str(exc))
        return result

    @bp.errorhandler(400)
    @bp.errorhandler(401)
    @bp.errorhandler(404)
    @bp.errorhandler(409)
    @bp.errorhandler(413)
    def api_error(error):
        return {"error": error.description}, error.code

    return bp
