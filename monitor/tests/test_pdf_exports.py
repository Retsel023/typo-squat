"""Offline PDF exports embed saved images and preserve report boundaries."""

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from PIL import Image

from typo_monitor.pdf_export import capture_image_bytes, client_pdf
from typo_monitor.report_exports import inventory_records, report_records
from typo_monitor.store import Store
from typo_monitor.web import create_app


class PdfExportTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.store = Store(self.root)
        self.project = self.store.create_project("Client Café & partners", ["example.com"])
        self.domain = "alpha.example"
        self.first = self.scan()
        for capture in self.store.list_run_captures(self.first["id"]):
            path = self.root / "runs" / capture["run_id"] / capture["relative_path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            Image.new("RGB", (160, 90), "red" if capture["scheme"] == "http" else "blue").save(path)
        self.client = create_app(SimpleNamespace(store=self.store, data_dir=self.root)).test_client()

    def scan(self, *, address="192.0.2.1", status="captured", change="first_observation"):
        run = self.store.start_run(self.project["id"])
        captures = [{"scheme": scheme, "url": f"{scheme}://{self.domain}", "status": status,
                     "title": "Client Café", "http_status": 200,
                     "relative_path": f"screenshots/{scheme}.png" if status == "captured" else None,
                     "preflight": {"status": "http_response", "title_status": "found", "title": "Client Café",
                                   "title_http_status": 200, "web_change": change, "content_change": change,
                                   "capture_reason": change}}
                    for scheme in ("http", "https")]
        return self.store.finish_run(run["id"], seeds=["example.com"], candidates=[self.domain],
            observations={self.domain: {"status": "resolved", "records": [["A", address]]}},
            source_status={"dns": {"status": "ok"}}, screenshots={self.domain: captures},
            provenance={self.domain: ["example.com"]})

    def assert_pdf(self, response, *, images):
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pdf")
        self.assertIn("attachment", response.headers["Content-Disposition"])
        data = response.get_data()
        self.assertTrue(data.startswith(b"%PDF-"))
        self.assertEqual(data.count(b"/Subtype /Image"), images)
        self.assertTrue(data.rstrip().endswith(b"%%EOF"))

    def test_inventory_pdf_embeds_both_protocol_images_without_network_or_ai(self):
        with patch("typo_monitor.pdf_export.client_pdf", wraps=client_pdf) as export, \
             patch("requests.sessions.Session.request", side_effect=AssertionError("No network during export")), \
             patch("typo_monitor.web.review_selection", side_effect=AssertionError("No AI selection during export")):
            response = self.client.get(f"/projects/{self.project['id']}/export.pdf?q=alpha&screenshots=with")
        self.assert_pdf(response, images=2)
        records = export.call_args.args[1]
        self.assertEqual([row["domain"] for row in records], [self.domain])
        self.assertEqual(set(records[0]["endpoints"]), {"http", "https"})
        empty = self.client.get(f"/projects/{self.project['id']}/export.pdf?q=not-present")
        self.assert_pdf(empty, images=0)

    def test_historical_report_uses_own_dns_images_and_no_inventory_fallback(self):
        latest = self.scan(address="192.0.2.9", status="skipped", change="unchanged")
        snapshot = self.store.report_export_snapshot(self.first["id"])
        records = report_records(self.project, snapshot["run"], snapshot["captures"], snapshot["observations"], website_view="all")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["dns_now"], "A 192.0.2.1")
        self.assertEqual({endpoint["image"]["run_id"] for endpoint in records[0]["endpoints"].values()}, {self.first["id"]})
        self.assert_pdf(self.client.get(f"/runs/{self.first['id']}/export.pdf?website_view=all"), images=2)

        current = self.store.report_export_snapshot(latest["id"])
        records = report_records(self.project, current["run"], current["captures"], current["observations"])
        self.assertEqual(records[0]["dns_before"], "A 192.0.2.1")
        self.assertEqual(records[0]["dns_now"], "A 192.0.2.9")
        self.assertTrue(all(endpoint["image"] is None for endpoint in records[0]["endpoints"].values()))
        self.assert_pdf(self.client.get(f"/runs/{latest['id']}/export.pdf"), images=0)
        inventory = list(inventory_records(self.store.export_domains(self.project["id"])))
        self.assertTrue(all(endpoint["previous_image"] for endpoint in inventory[0]["endpoints"].values()))

    def test_missing_or_corrupt_images_still_produce_a_readable_pdf(self):
        for capture in self.store.list_run_captures(self.first["id"]):
            path = self.root / "runs" / capture["run_id"] / capture["relative_path"]
            if capture["scheme"] == "http":
                path.unlink()
            else:
                path.write_bytes(b"\x89PNG\r\n\x1a\ninvalid image")
        self.assert_pdf(self.client.get(f"/runs/{self.first['id']}/export.pdf?website_view=all"), images=0)

    def test_pdf_routes_reject_unfinished_deleted_invalid_views_and_unknown_projects(self):
        pending = self.store.start_run(self.project["id"])
        self.assertEqual(self.client.get(f"/runs/{pending['id']}/export.pdf").status_code, 409)
        self.store.fail_run(pending["id"], "Offline fixture")
        self.assertEqual(self.client.get(f"/runs/{self.first['id']}/export.pdf?body_view=invalid").status_code, 400)
        self.assertEqual(self.client.get(f"/projects/{uuid4()}/export.pdf").status_code, 404)
        self.store.delete_report(self.first["id"])
        self.assertEqual(self.client.get(f"/runs/{self.first['id']}/export.pdf").status_code, 404)

    def test_image_reader_rejects_cross_project_traversal_and_symlink_paths(self):
        capture = self.store.list_run_captures(self.first["id"])[0]
        expected = {"project_id": self.project["id"], "domain": self.domain, "scheme": capture["scheme"]}
        self.assertTrue(capture_image_bytes(self.root, capture, **expected).startswith(b"\x89PNG"))
        for changed in ({"project_id": str(uuid4())}, {"domain": "other.example"},
                        {"relative_path": "../outside.png"}, {"run_id": "../outside"}):
            self.assertIsNone(capture_image_bytes(self.root, {**capture, **changed}, **expected))
        outside = self.root / "outside.png"
        Image.new("RGB", (10, 10), "green").save(outside)
        link = self.root / "runs" / capture["run_id"] / "linked.png"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks are unavailable on this platform")
        self.assertIsNone(capture_image_bytes(self.root, {**capture, "relative_path": "linked.png"}, **expected))
