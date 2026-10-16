import base64
import hashlib
from io import BytesIO
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from PIL import Image

from typo_monitor.store import Store
from typo_monitor.web import create_app


class FakeService:
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)
        self.store = Store(self.data_dir)
        self.submissions = []

    def submit_scan(self, project_id):
        self.submissions.append(project_id)
        return self.store.start_run(project_id)

    def create_project(self, name, roots):
        return self.store.create_project(name, roots)

    def tool_status(self):
        return {}


class AutomationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.service = FakeService(self.temp.name)
        self.project = self.service.create_project("Example", ["example.com"])
        self.api_token = secrets.token_hex(24)
        environment = patch.dict(os.environ, {"TYPO_MONITOR_API_TOKEN": self.api_token})
        environment.start()
        self.addCleanup(environment.stop)
        self.app = create_app(self.service)
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()
        self.authorization = {"Authorization": "Bearer " + self.api_token}

    def get(self, path, **kwargs):
        return self.client.get(path, headers=self.authorization, **kwargs)

    def post(self, path, **kwargs):
        return self.client.post(path, headers=self.authorization, **kwargs)

    @staticmethod
    def capture(domain, scheme="https", *, change="first_capture", previous=None, duplicate=False, status="captured", color="white"):
        return {"scheme": scheme, "url": f"{scheme}://{domain}", "status": status,
                "relative_path": f"screenshots/{scheme}-{domain}.png" if status == "captured" else None,
                "title": "Fixture page", "http_status": 200 if status == "captured" else None,
                "error": None, "captured_at": "2026-10-16T12:00:00Z", "_color": color,
                "visual": {"change": change, "previous_run_id": previous,
                           "duplicate_of": "https" if duplicate else None,
                           "duplicate_kind": "exact" if duplicate else None}}

    def complete_run(self, captures, *, timestamp="2026-10-16T12:00:00Z", parked=()):
        run = self.service.store.start_run(self.project["id"])
        workdir = self.service.data_dir / "runs" / run["id"]
        for attempts in captures.values():
            for capture in attempts:
                capture["captured_at"] = timestamp
                color = capture.pop("_color", "white")
                if capture["status"] == "captured":
                    path = workdir / capture["relative_path"]
                    path.parent.mkdir(parents=True, exist_ok=True)
                    image = Image.new("RGB", (8, 6), color)
                    image.save(path)
                    pixel_digest = hashlib.sha256(b"RGB:8x6\0" + image.tobytes()).hexdigest()
                    capture["visual"].setdefault("pixel_sha256", pixel_digest)
        return self.service.store.finish_run(run["id"], seeds=["example.com"], candidates=list(captures),
            observations={domain: {"status": "resolved", "records": [["A", "192.0.2.1"]],
                          "parking": {"status": "likely_parked" if domain in parked else "not_detected", "evidence": []}}
                          for domain in captures},
            source_status={"dns": {"status": "ok"}}, screenshots=captures)

    def fixture_manifest(self):
        old = self.complete_run({"changed.example": [self.capture("changed.example"), self.capture("changed.example", "http")]},
                                timestamp="2026-10-16T11:00:00Z")
        current = self.complete_run({
            "changed.example": [self.capture("changed.example", change="changed", previous=old["id"], color="blue"),
                                self.capture("changed.example", "http", change="changed", previous=old["id"], duplicate=True, color="blue")],
            "first.example": [self.capture("first.example")],
            "same.example": [self.capture("same.example", change="unchanged")],
            "uncertain.example": [self.capture("uncertain.example", change="uncertain")],
            "failed.example": [self.capture("failed.example", change="changed", status="failed")],
        })
        return old, current

    def assert_no_token(self, response):
        self.assertFalse(self.api_token in response.get_data(as_text=True), "API response exposed its authentication token")

    def test_api_disabled_without_a_long_token_and_wrong_bearer_rejected(self):
        for value in ("", "too-short"):
            with self.subTest(configured=bool(value)), patch.dict(os.environ, {"TYPO_MONITOR_API_TOKEN": value}):
                app = create_app(self.service)
                app.config.update(TESTING=True)
                response = app.test_client().get("/api/projects", headers=self.authorization)
                self.assertEqual(response.status_code, 404)
                self.assert_no_token(response)
        for headers in ({}, {"Authorization": "Bearer invalid"}, {"Authorization": self.api_token}):
            response = self.client.get("/api/projects", headers=headers)
            self.assertEqual(response.status_code, 401)
            self.assert_no_token(response)

    def test_project_scan_and_run_status_flow(self):
        response = self.get("/api/projects")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["projects"][0]["id"], self.project["id"])
        self.assertEqual(set(response.json["projects"][0]), {"id", "name"})
        response = self.post("/api/scans", json={"project_id": self.project["id"]})
        self.assertEqual(response.status_code, 202)
        run = response.json
        self.assertEqual(run["status"], "running")
        self.assertEqual(self.service.submissions, [self.project["id"]])
        self.assertEqual(self.get(f"/api/runs/{run['id']}").json, run)
        self.assertEqual(self.post("/api/scans", json={"project_id": self.project["id"]}).status_code, 409)
        self.assertEqual(self.get(f"/api/runs/{run['id']}/review").status_code, 409)

    def test_finished_run_status_omits_event_history_and_source_details(self):
        _, current = self.fixture_manifest()
        self.assertTrue(current["events"])
        response = self.get(f"/api/runs/{current['id']}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json), {"id", "project_id", "status", "started_at", "finished_at", "counts", "error"})
        self.assertEqual(response.json["counts"], current["counts"])
        self.assertNotIn("events", response.json)
        self.assertNotIn("source_status", response.json)

    def test_invalid_scan_bodies_and_missing_run_return_controlled_errors(self):
        for body in (None, [], {}, {"project_id": "not-a-uuid"}):
            with self.subTest(body=body):
                response = self.post("/api/scans", json=body)
                self.assertEqual(response.status_code, 400)
                self.assert_no_token(response)
        self.assertEqual(self.post("/api/scans", data="{", content_type="application/json").status_code, 400)
        self.assertEqual(self.post("/api/scans", json={"project_id": str(uuid4())}).status_code, 404)
        self.assertEqual(self.get(f"/api/runs/{uuid4()}").status_code, 404)

    def test_review_manifest_filters_new_and_changed_and_never_reads_images_by_default(self):
        old, current = self.fixture_manifest()
        with (patch("pathlib.Path.read_bytes", side_effect=AssertionError("Metadata must not read images")),
              patch("pathlib.Path.open", side_effect=AssertionError("Metadata must not open images"))):
            response = self.get(f"/api/runs/{current['id']}/review")
        self.assertEqual(response.status_code, 200)
        manifest = response.json
        self.assertEqual(manifest["run_id"], current["id"])
        self.assertEqual(manifest["total"], 2)
        self.assertIsNone(manifest["next_offset"])
        self.assertEqual([(item["domain"], item["scheme"], item["visual_status"]) for item in manifest["items"]],
                         [("changed.example", "https", "changed"), ("first.example", "https", "new")])
        self.assertEqual(manifest["items"][0]["previous"]["run_id"], old["id"])
        self.assertIsNone(manifest["items"][1]["previous"])
        self.assertEqual(manifest["items"][0]["references"], [])
        self.assertNotIn("data:image/", response.get_data(as_text=True))
        self.assert_no_token(response)

    def test_review_pagination_and_explicit_filtering(self):
        _, current = self.fixture_manifest()
        route = f"/api/runs/{current['id']}/review"
        first = self.get(route, query_string={"limit": 1}).json
        self.assertEqual(first["total"], 2)
        self.assertEqual(first["next_offset"], 1)
        second = self.get(route, query_string={"limit": 1, "offset": first["next_offset"]}).json
        self.assertEqual(second["items"][0]["domain"], "first.example")
        self.assertIsNone(second["next_offset"])
        filtered = self.get(route, query_string={"domain": "CHANGED.Example.", "scheme": "https"}).json
        self.assertEqual(filtered["total"], 1)
        self.assertEqual(filtered["items"][0]["domain"], "changed.example")
        for query in ({"limit": 0}, {"limit": 1001}, {"limit": "all"}, {"offset": -1},
                      {"offset": "bad"}, {"scheme": "file"}, {"domain": "https://example.com"}):
            with self.subTest(query=query):
                self.assertEqual(self.get(route, query_string=query).status_code, 400)

    def test_changed_http_keeps_history_when_exact_https_representative_is_unchanged(self):
        domain = "changed.example"
        old = self.complete_run({domain: [self.capture(domain, "http", color="white"), self.capture(domain, color="blue")]},
                                timestamp="2026-10-16T11:00:00Z")
        current = self.complete_run({domain: [
            self.capture(domain, "http", change="changed", previous=old["id"], duplicate=True, color="blue"),
            self.capture(domain, change="unchanged", previous=old["id"], color="blue")]})
        with (patch("pathlib.Path.read_bytes", side_effect=AssertionError("Metadata must not read images")),
              patch("pathlib.Path.open", side_effect=AssertionError("Metadata must not open images"))):
            response = self.get(f"/api/runs/{current['id']}/review")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["total"], 1)
        item = response.json["items"][0]
        self.assertEqual(item["scheme"], "http")
        self.assertEqual(item["visual_status"], "changed")
        self.assertEqual(item["previous"]["scheme"], "http")
        self.assertEqual(item["previous"]["run_id"], old["id"])

    def test_identical_current_images_keep_both_changes_when_previous_pixels_differ(self):
        domain = "changed.example"
        old = self.complete_run({domain: [self.capture(domain, "http", color="red"), self.capture(domain, color="white")]},
                                timestamp="2026-10-16T11:00:00Z")
        current = self.complete_run({domain: [
            self.capture(domain, "http", change="changed", previous=old["id"], duplicate=True, color="blue"),
            self.capture(domain, change="changed", previous=old["id"], color="blue")]})
        response = self.get(f"/api/runs/{current['id']}/review")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["total"], 2)
        http, https = response.json["items"]
        self.assertEqual((http["scheme"], https["scheme"]), ("http", "https"))
        self.assertEqual(http["current"]["visual"]["pixel_sha256"], https["current"]["visual"]["pixel_sha256"])
        self.assertNotEqual(http["previous"]["visual"]["pixel_sha256"], https["previous"]["visual"]["pixel_sha256"])

    def test_exact_protocol_duplicates_collapse_when_both_are_first_captures(self):
        domain = "first.example"
        current = self.complete_run({domain: [self.capture(domain, "http", duplicate=True), self.capture(domain)]})
        response = self.get(f"/api/runs/{current['id']}/review")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["total"], 1)
        self.assertEqual(response.json["items"][0]["scheme"], "https")

    def test_inline_images_require_one_explicit_pair_and_include_current_and_previous(self):
        _, current = self.fixture_manifest()
        route = f"/api/runs/{current['id']}/review"
        for query in ({"include_images": "1"}, {"include_images": "1", "domain": "changed.example"},
                      {"include_images": "1", "scheme": "https"}):
            with self.subTest(query=query):
                self.assertEqual(self.get(route, query_string=query).status_code, 400)
        response = self.get(route, query_string={"include_images": "1", "domain": "changed.example", "scheme": "https"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["total"], 1)
        item = response.json["items"][0]
        for name, color in (("current", (0, 0, 255)), ("previous", (255, 255, 255))):
            image_url = item[name]["image_data_url"]
            self.assertTrue(image_url.startswith("data:image/png;base64,"))
            with Image.open(BytesIO(base64.b64decode(image_url.split(",", 1)[1], validate=True))) as image:
                self.assertEqual(image.size, (8, 6))
                self.assertEqual(image.convert("RGB").getpixel((0, 0)), color)
        self.assert_no_token(response)

    def test_path_escape_is_not_transferred_and_failure_does_not_expose_filesystem_details(self):
        _, current = self.fixture_manifest()
        with self.service.store._connection(write=True) as db:
            db.execute("UPDATE captures SET relative_path='../outside.png' WHERE run_id=? AND domain=? AND scheme='https'",
                       (current["id"], "changed.example"))
        outside = self.service.data_dir / "runs" / "outside.png"
        Image.new("RGB", (8, 6), "red").save(outside)
        response = self.get(f"/api/runs/{current['id']}/review", query_string={
            "include_images": "1", "domain": "changed.example", "scheme": "https"})
        self.assertEqual(response.status_code, 200)
        capture = response.json["items"][0]["current"]
        self.assertNotIn("image_data_url", capture)
        self.assertIn("image_error", capture)
        self.assertNotIn(str(self.service.data_dir), response.get_data(as_text=True))
        self.assert_no_token(response)

    def test_symlinked_runs_directory_cannot_transfer_images_outside_data_directory(self):
        _, current = self.fixture_manifest()
        external = tempfile.TemporaryDirectory()
        self.addCleanup(external.cleanup)
        runs = self.service.data_dir / "runs"
        relocated = Path(external.name) / "runs"
        runs.rename(relocated)
        try:
            runs.symlink_to(relocated, target_is_directory=True)
        except OSError:
            self.skipTest("Symlinks unavailable on this platform")
        response = self.get(f"/api/runs/{current['id']}/review", query_string={
            "include_images": "1", "domain": "changed.example", "scheme": "https"})
        self.assertEqual(response.status_code, 200)
        for name in ("current", "previous"):
            capture = response.json["items"][0][name]
            self.assertNotIn("image_data_url", capture)
            self.assertIn("image_error", capture)
        self.assert_no_token(response)

    def test_review_submission_persists_provider_result_with_timestamp(self):
        _, current = self.fixture_manifest()
        body = {"domain": "changed.example", "scheme": "https", "provider": "Fixture provider", "model": "fixture-vision",
                "summary": "The capture shows a different page layout.", "risk": "uncertain", "changed": True, "confidence": 0.8}
        response = self.post(f"/api/runs/{current['id']}/reviews", json=body)
        self.assertEqual(response.status_code, 200)
        analysis = response.json["analysis"]
        for key in ("provider", "model", "summary", "risk", "changed", "confidence"):
            self.assertEqual(analysis[key], body[key])
        self.assertTrue(analysis["reviewed_at"])
        self.assertEqual(self.service.store.get_capture(current["id"], "changed.example", "https")["analysis"], analysis)
        self.assert_no_token(response)

    def test_default_handoff_skips_parked_and_reviewed_with_explicit_inclusion_options(self):
        current = self.complete_run({domain: [self.capture(domain)] for domain in (
            "active.example", "parked.example", "reviewed.example")}, parked={"parked.example"})
        self.service.store.save_capture_review(current["id"], "reviewed.example", "https", {
            "provider": "Fixture", "model": "fixture", "summary": "Already reviewed", "risk": "low"})
        route = f"/api/runs/{current['id']}/review"
        response = self.get(route)
        self.assertEqual(response.status_code, 200)
        self.assertEqual([item["domain"] for item in response.json["items"]], ["active.example"])
        self.assertEqual(response.json["summary"]["excluded"]["parked"], 1)
        self.assertEqual(response.json["summary"]["excluded"]["reviewed"], 1)
        included = self.get(route, query_string={"include_parked": 1, "include_reviewed": 1})
        self.assertEqual(included.json["total"], 3)

    def test_capture_metadata_retains_pixel_identity_without_local_diagnostic_paths(self):
        capture = self.capture("first.example")
        capture["visual"]["error"] = str(self.service.data_dir / "private" / "diagnostic.png")
        current = self.complete_run({"first.example": [capture]})
        response = self.get(f"/api/runs/{current['id']}/review")
        self.assertEqual(response.status_code, 200)
        visual = response.json["items"][0]["current"]["visual"]
        self.assertEqual(visual["pixel_sha256"], capture["visual"]["pixel_sha256"])
        self.assertNotIn("error", visual)
        self.assertNotIn(str(self.service.data_dir), response.get_data(as_text=True))

    def test_invalid_provider_reviews_are_rejected_without_overwriting_assessment(self):
        _, current = self.fixture_manifest()
        route = f"/api/runs/{current['id']}/reviews"
        valid = {"domain": "changed.example", "scheme": "https", "provider": "Fixture", "model": "fixture",
                 "summary": "Fixture assessment", "risk": "low", "changed": None, "confidence": 0.5}
        self.assertEqual(self.post(route, json=valid).status_code, 200)
        before = self.service.store.get_capture(current["id"], "changed.example", "https")["analysis"]
        for updates in ({"risk": "critical"}, {"changed": "yes"}, {"confidence": 2}, {"confidence": True},
                        {"provider": ""}, {"model": None}, {"summary": ""}, {"scheme": "ftp"}):
            with self.subTest(updates=updates):
                response = self.post(route, json={**valid, **updates})
                self.assertEqual(response.status_code, 400)
                self.assert_no_token(response)
        self.assertEqual(self.post(route, json=[]).status_code, 400)
        self.assertEqual(self.service.store.get_capture(current["id"], "changed.example", "https")["analysis"], before)

    def test_bearer_authentication_does_not_disable_form_csrf(self):
        response = self.client.post("/projects", headers=self.authorization,
                                    data={"name": "No token", "domains": "example.com"})
        self.assertEqual(response.status_code, 400)
        self.client.get("/")
        with self.client.session_transaction() as session:
            csrf = session["csrf_token"]
        response = self.client.get("/api/projects", headers={"X-CSRF-Token": csrf})
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
