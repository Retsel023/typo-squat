from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from typo_monitor.handoff import review_selection
from typo_monitor.store import Store


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name))
        self.project = self.store.create_project("Example", ["example.com"])

    @staticmethod
    def capture(domain, scheme="https", *, change="first_capture", digest="a", old=None, duplicate=False, status="captured"):
        return {"scheme": scheme, "url": f"{scheme}://{domain}", "status": status,
                "relative_path": f"screenshots/{scheme}-{domain}.png" if status == "captured" else None,
                "captured_at": "2026-10-16T12:00:00Z",
                "visual": {"change": change, "pixel_sha256": digest * 64 if digest else None,
                           "previous_run_id": old, "duplicate_of": "https" if duplicate else None,
                           "duplicate_kind": "exact" if duplicate else None}}

    def complete(self, captures, *, seeds=None, provenance=None, parked=(), project=None):
        project = project or self.project
        run = self.store.start_run(project["id"])
        return self.store.finish_run(run["id"], seeds=seeds or ["example.com"], candidates=list(captures),
            observations={domain: {"status": "resolved", "records": [["A", "192.0.2.1"]],
                "parking": {"status": "likely_parked" if domain in parked else "not_detected", "evidence": []}}
                for domain in captures}, source_status={"dns": {"status": "ok"}},
            screenshots=captures, provenance=provenance)

    def assess(self, run, domain):
        self.store.save_capture_review(run["id"], domain, "https", {"provider": "Fixture", "model": "fixture",
            "summary": "Already assessed locally", "risk": "low", "changed": None, "confidence": 0.7})

    def test_one_exclusion_per_capture_with_clear_priority_and_no_asset_reads(self):
        run = self.complete({
            "example.com": [self.capture("example.com", status="failed", change="unchanged")],
            "failed.example": [self.capture("failed.example", status="failed", change="changed")],
            "same.example": [self.capture("same.example", change="unchanged")],
            "uncertain.example": [self.capture("uncertain.example", change="uncertain")],
            "parked.example": [self.capture("parked.example")],
            "reviewed.example": [self.capture("reviewed.example")],
            "selected.example": [self.capture("selected.example")],
            "duplicate.example": [self.capture("duplicate.example", "http", duplicate=True), self.capture("duplicate.example")],
        }, parked={"parked.example"})
        self.assess(run, "reviewed.example")
        self.assess(run, "parked.example")
        with (patch("pathlib.Path.open", side_effect=AssertionError("Selection must not read assets")),
              patch("pathlib.Path.read_bytes", side_effect=AssertionError("Selection must not read assets"))):
            result = review_selection(self.store, run["id"])
        self.assertEqual(result["summary"], {"total_captures": 9, "selected_pairs": 2,
            "excluded": {"original": 1, "failed": 1, "unchanged": 1, "uncertain": 1,
                         "duplicate": 1, "parked": 1, "reviewed": 1}})
        self.assertEqual([(item["domain"], item["scheme"]) for item in result["items"]],
                         [("duplicate.example", "https"), ("selected.example", "https")])

    def test_parked_and_reviewed_inclusion_are_separate_explicit_options(self):
        run = self.complete({"parked.example": [self.capture("parked.example")],
                             "reviewed.example": [self.capture("reviewed.example")]}, parked={"parked.example"})
        self.assess(run, "reviewed.example")
        self.assertEqual(review_selection(self.store, run["id"])["items"], [])
        parked = review_selection(self.store, run["id"], include_parked=True)
        self.assertEqual([item["domain"] for item in parked["items"]], ["parked.example"])
        reviewed = review_selection(self.store, run["id"], include_reviewed=True)
        self.assertEqual([item["domain"] for item in reviewed["items"]], ["reviewed.example"])
        self.assertEqual(review_selection(self.store, run["id"], include_parked=True, include_reviewed=True)["summary"]["selected_pairs"], 2)

    def test_exact_duplicate_changes_collapse_only_when_both_previous_images_match(self):
        domain = "changed.example"
        old = self.complete({domain: [self.capture(domain, "http"), self.capture(domain)]})
        current = self.complete({domain: [self.capture(domain, "http", change="changed", digest="b", old=old["id"], duplicate=True),
                                          self.capture(domain, change="changed", digest="b", old=old["id"])]})
        result = review_selection(self.store, current["id"])
        self.assertEqual([item["scheme"] for item in result["items"]], ["https"])
        self.assertEqual(result["summary"]["excluded"]["duplicate"], 1)
        self.assertEqual(result["items"][0]["previous"]["run_id"], old["id"])

    def test_identical_current_images_keep_distinct_prior_protocol_histories(self):
        domain = "changed.example"
        old = self.complete({domain: [self.capture(domain, "http", digest="a"), self.capture(domain, digest="c")]})
        current = self.complete({domain: [self.capture(domain, "http", change="changed", digest="b", old=old["id"], duplicate=True),
                                          self.capture(domain, change="changed", digest="b", old=old["id"])]})
        result = review_selection(self.store, current["id"])
        self.assertEqual([item["scheme"] for item in result["items"]], ["http", "https"])
        self.assertEqual(result["summary"]["excluded"]["duplicate"], 0)
        self.assertNotEqual(result["items"][0]["previous"]["visual"]["pixel_sha256"],
                            result["items"][1]["previous"]["visual"]["pixel_sha256"])

    def test_changed_http_not_lost_when_matching_https_image_is_unchanged(self):
        domain = "changed.example"
        old = self.complete({domain: [self.capture(domain, "http", digest="a"), self.capture(domain, digest="b")]})
        current = self.complete({domain: [self.capture(domain, "http", change="changed", digest="b", old=old["id"], duplicate=True),
                                          self.capture(domain, change="unchanged", digest="b", old=old["id"])]})
        result = review_selection(self.store, current["id"])
        self.assertEqual([item["scheme"] for item in result["items"]], ["http"])
        self.assertEqual(result["summary"]["excluded"]["unchanged"], 1)

    def test_unknown_prior_pixel_identity_does_not_collapse_changes(self):
        domain = "changed.example"
        old = self.complete({domain: [self.capture(domain, "http", digest=None), self.capture(domain, digest=None)]})
        current = self.complete({domain: [self.capture(domain, "http", change="changed", digest="b", old=old["id"], duplicate=True),
                                          self.capture(domain, change="changed", digest="b", old=old["id"])]})
        self.assertEqual(review_selection(self.store, current["id"])["summary"]["selected_pairs"], 2)

    def test_only_one_source_reference_prefers_https_and_falls_back_to_http(self):
        domain = "selected.example"
        run = self.complete({domain: [self.capture(domain)],
            "example.com": [self.capture("example.com", status="failed"), self.capture("example.com", "http")],
            "portal.example.com": [self.capture("portal.example.com")]},
            seeds=["example.com", "portal.example.com"], provenance={domain: ["example.com", "portal.example.com"]})
        result = review_selection(self.store, run["id"])
        self.assertEqual(len(result["items"]), 1)
        references = result["items"][0]["references"]
        self.assertEqual([(capture["domain"], capture["scheme"]) for capture in references], [("example.com", "http")])

    def test_previous_capture_from_another_project_is_not_handed_off(self):
        domain = "changed.example"
        other = self.store.create_project("Other", ["example.com"])
        old = self.complete({domain: [self.capture(domain)]}, project=other)
        current = self.complete({domain: [self.capture(domain, change="changed", digest="b", old=old["id"])]})
        self.assertIsNone(review_selection(self.store, current["id"])["items"][0]["previous"])

    def test_missing_or_running_run_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "not found"):
            review_selection(self.store, "missing")
        run = self.store.start_run(self.project["id"])
        with self.assertRaisesRegex(ValueError, "still running"):
            review_selection(self.store, run["id"])


if __name__ == "__main__":
    unittest.main()
