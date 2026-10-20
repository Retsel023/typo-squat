"""Offline integration coverage for complete filtered views and client CSVs."""

import csv
import io
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from typo_monitor.store import Store
from typo_monitor.web import create_app


SUCCESS = {"discovery": {"status": "ok"}, "dns": {"status": "ok"}}


class InventoryFilterTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = Store(Path(directory.name))
        self.project = self.store.create_project("Client example", ["example.com"])
        self.pid = self.project["id"]
        self.domains = ["alpha.example", "beta.example", "park.example"]
        first = {name: [self.capture(name, scheme) for scheme in ("http", "https")] for name in self.domains}
        self.baseline = self.scan(self.domains, first)
        self.domains.append("new.example")
        captures = {
            "alpha.example": [self.capture("alpha.example", scheme, status="skipped", change="unchanged")
                              for scheme in ("http", "https")],
            "beta.example": [self.capture("beta.example", scheme, change="structure_changed", similarity=40)
                             for scheme in ("http", "https")],
            "park.example": [self.capture("park.example", scheme, status="skipped", skip="title_rule", title="GoDaddy")
                             for scheme in ("http", "https")],
            "new.example": [self.capture("new.example", "https", status="failed")],
        }
        self.latest = self.scan(self.domains, captures, alpha_address="192.0.2.9")

    @staticmethod
    def capture(domain, scheme, *, status="captured", change="first_observation", similarity=100, skip=None, title="Brand Café %_"):
        probe = {"status": "http_response", "title_status": "found", "title": title, "title_http_status": 200,
                 "web_change": change, "content_change": change,
                 "capture_reason": skip or change, "layout_similarity": similarity,
                 "structure_comparison": "changed" if similarity < 100 else "unchanged"}
        if skip:
            probe["skip_reason"] = skip
        if change != "first_observation":
            probe.update(previous_known_title=title, previous_known_title_status="found")
        return {"scheme": scheme, "url": f"{scheme}://{domain}", "status": status, "http_status": 200,
                "title": title if status == "captured" else None, "preflight": probe,
                "relative_path": f"screenshots/{domain}-{scheme}.png" if status == "captured" else None}

    def scan(self, domains, captures, *, alpha_address="192.0.2.1"):
        run = self.store.start_run(self.pid)
        return self.store.finish_run(run["id"], seeds=["example.com"], candidates=domains,
            observations={name: {"status": "resolved", "records": [["A", alpha_address if name == "alpha.example" else "192.0.2.1"]]}
                          for name in domains}, source_status=SUCCESS, screenshots=captures,
            provenance={name: ["example.com"] for name in domains})

    def names(self, **filters):
        return [item["domain"] for item in self.store.export_domains(self.pid, **filters)]

    def test_screenshot_filter_keeps_older_visible_image_and_filters_before_paging(self):
        result = self.store.query_domains(self.pid, screenshots="with", limit=1, offset=1)
        self.assertEqual(result["total"], 2)
        self.assertEqual([row["domain"] for row in result["items"]], ["beta.example"])
        self.assertEqual(self.names(screenshots="with"), ["alpha.example", "beta.example"])
        self.assertEqual(self.names(screenshots="without"), ["new.example", "park.example"])
        self.assertEqual(self.store.source_groups(self.pid, screenshots="with"), [{"seed": "example.com", "total": 2}])
        self.assertEqual(self.names(screenshots="latest"), ["beta.example"])

    def test_changes_are_latest_scan_scoped_and_dns_only_requires_unchanged_protocols(self):
        self.assertEqual(self.names(activity="new"), ["new.example"])
        self.assertEqual(self.names(activity="records"), ["alpha.example"])
        self.assertEqual(self.names(activity="dns_only"), ["alpha.example"])
        self.assertEqual(self.names(activity="layout"), ["beta.example"])
        changed = [self.capture("alpha.example", "http", status="skipped", change="unchanged"),
                   {**self.capture("alpha.example", "https", status="failed", change="unknown"),
                    "preflight": {"status": "unknown", "web_change": "unknown"}}]
        self.scan(self.domains, {"alpha.example": changed}, alpha_address="192.0.2.10")
        self.assertEqual(self.names(activity="dns_only"), [])
        self.assertEqual(self.names(activity="dns_only", protocol="http"), ["alpha.example"])

    def test_title_search_is_literal_case_insensitive_and_preserved_in_export(self):
        self.assertEqual(self.names(query="CAFÉ %_", screenshots="with"), ["alpha.example", "beta.example"])
        self.assertEqual(self.names(exclude_q="café %_"), ["park.example"])
        self.assertEqual(self.names(query="%' OR 1=1 --"), [])
        self.assertEqual(self.names(exclusions="only"), ["park.example"])
        self.assertEqual(self.names(exclusions="hide"), ["alpha.example", "beta.example", "new.example"])
        self.store.set_global_capture_filter(enabled=True, rules=["Café"])
        self.assertEqual(self.names(exclusions="hide"), [])

    def test_filtered_csv_includes_all_matching_rows_and_image_dates_without_ai(self):
        client = create_app(SimpleNamespace(store=self.store)).test_client()
        with patch("typo_monitor.web.review_selection", side_effect=AssertionError("CSV must not invoke AI selection")):
            response = client.get(f"/projects/{self.pid}/export.csv?screenshots=with&sort=domain_desc")
        self.assertEqual(response.status_code, 200)
        rows = list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))
        self.assertEqual([row["domain"] for row in rows], ["beta.example", "alpha.example"])
        self.assertEqual(rows[1]["http_screenshot_available"], "yes")
        self.assertTrue(rows[1]["http_screenshot_captured_at"])

    def test_report_export_retains_old_dns_values_and_rejects_deleted_or_unfinished_reports(self):
        client = create_app(SimpleNamespace(store=self.store)).test_client()
        response = client.get(f"/runs/{self.baseline['id']}/export.csv?website_view=all")
        self.assertEqual(response.status_code, 200)
        rows = list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))
        website = next(row for row in rows if row["domain"] == "alpha.example" and row["section"] == "website")
        self.assertEqual(website["dns_records"], "A 192.0.2.1")
        self.assertEqual(website["screenshot_available"], "yes")
        self.assertEqual(rows[0]["section"], "scan_summary")
        pending = self.store.start_run(self.pid)
        self.assertEqual(client.get(f"/runs/{pending['id']}/export.csv").status_code, 409)
        self.store.fail_run(pending["id"], "Offline fixture")
        self.store.delete_report(self.baseline["id"])
        self.assertEqual(client.get(f"/runs/{self.baseline['id']}/export.csv").status_code, 404)

    def test_filters_and_export_stay_in_the_selected_project(self):
        other = self.store.create_project("=Other client", ["other.example"])
        run = self.store.start_run(other["id"])
        self.store.finish_run(run["id"], seeds=["other.example"], candidates=["private.example"],
            observations={"private.example": {"status": "resolved", "records": [["A", "192.0.2.100"]]}},
            source_status=SUCCESS, screenshots={"private.example": [self.capture("private.example", "https")]})
        self.assertNotIn("private.example", self.names(query="Café"))
        snapshot = self.store.report_export_snapshot(self.latest["id"])
        self.assertNotIn("private.example", snapshot["observations"])
        response = create_app(SimpleNamespace(store=self.store)).test_client().get(f"/runs/{run['id']}/export.csv")
        rows = list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))
        self.assertEqual(rows[0]["project"], "'=Other client")
