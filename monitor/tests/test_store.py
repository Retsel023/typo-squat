from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
from uuid import UUID

from typo_monitor.store import Store


POSITIVE = {"status": "resolved", "records": [["A", "192.0.2.1"]]}
NEGATIVE = {"status": "nxdomain", "records": []}
UNKNOWN = {"status": "unknown", "records": [], "error": "DNS timeout"}
SUCCESS = {"discovery": {"status": "ok"}, "dns": {"status": "ok"}}
CAPTURE = {"scheme": "https", "url": "https://typo.example", "status": "captured",
           "relative_path": "screenshots/https-typo.png", "title": "Example page", "http_status": 200,
           "error": None, "captured_at": "2026-10-16T12:00:00.000000+00:00"}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name))
        self.project = self.store.create_project("Example", ["EXAMPLE.com."])
        self.project_id = self.project["id"]

    def scan(self, observations, *, seeds=None, candidates=None, sources=None, provenance=None, screenshots=None, generation=None):
        run = self.store.start_run(self.project_id)
        return self.store.finish_run(
            run["id"], seeds=seeds if seeds is not None else ["example.com"],
            candidates=candidates if candidates is not None else list(observations),
            observations=observations, source_status=SUCCESS if sources is None else sources,
            provenance=provenance,
            screenshots=screenshots,
            generation=generation,
        )

    def domain(self, domain="typo.example"):
        return next(row for row in self.store.get_domains(self.project_id) if row["domain"] == domain)

    def test_first_informative_run_is_baseline_and_persists(self):
        run = self.scan({"typo.example": POSITIVE})
        self.assertTrue(run["is_baseline"])
        self.assertEqual(run["events"], [])
        self.assertEqual(run["status"], "completed")
        reopened = Store(self.temp.name)
        self.assertEqual(reopened.get_run(run["id"]), run)
        self.assertEqual(reopened.get_domains(self.project_id)[0]["records"], POSITIVE["records"])
        self.assertEqual(reopened.get_project(self.project_id)["last_run"]["id"], run["id"])
        self.assertEqual(str(UUID(self.project_id)), self.project_id)
        self.assertEqual(str(UUID(run["id"])), run["id"])

    def test_all_unknown_scan_does_not_establish_baseline(self):
        self.assertFalse(self.scan({"typo.example": UNKNOWN})["is_baseline"])
        next_run = self.scan({"typo.example": POSITIVE})
        self.assertTrue(next_run["is_baseline"])
        self.assertEqual(next_run["events"], [])
        self.assertFalse(self.scan({"typo.example": POSITIVE})["is_baseline"])

    def test_failed_initial_scan_does_not_establish_baseline(self):
        pending = self.store.start_run(self.project_id)
        self.store.fail_run(pending["id"], "generator unavailable")
        first_observed = self.scan({"typo.example": POSITIVE})
        self.assertTrue(first_observed["is_baseline"])
        self.assertEqual(first_observed["events"], [])

    def test_fluctuating_discovery_accumulates_inventory_without_missing_event(self):
        self.scan({"typo.example": POSITIVE, "other.example": POSITIVE}, seeds=["example.com", "sub.example.com"])
        run = self.scan({"other.example": POSITIVE}, candidates=["other.example"],
                        sources={"discovery": {"status": "failed", "error": "quota"}})
        self.assertEqual(self.store.inventory(self.project_id),
                         {"seeds": ["example.com", "sub.example.com"],
                          "candidates": ["other.example", "typo.example"]})
        self.assertEqual(run["status"], "partial")
        self.assertEqual(run["events"], [])
        state = self.domain()
        self.assertEqual(state["records"], POSITIVE["records"])
        self.assertEqual(state["missing_count"], 0)
        self.assertEqual(state["status"], "unknown")

    def test_two_explicit_negatives_required_then_reappearance(self):
        self.scan({"typo.example": POSITIVE})
        first_negative = self.scan({"typo.example": NEGATIVE})
        self.assertEqual(first_negative["events"], [])
        self.assertEqual(self.domain()["status"], "pending_missing")
        self.assertEqual(self.domain()["records"], POSITIVE["records"])
        second_negative = self.scan({"typo.example": {"status": "noanswer", "records": []}})
        self.assertEqual([e["kind"] for e in second_negative["events"]], ["missing_confirmed"])
        self.assertEqual(self.domain()["status"], "missing")
        self.assertEqual(self.scan({"typo.example": NEGATIVE})["events"], [])
        recovered = self.scan({"typo.example": POSITIVE})
        self.assertEqual([e["kind"] for e in recovered["events"]], ["reappeared"])
        self.assertEqual(self.domain()["missing_count"], 0)

    def test_timeout_breaks_negative_streak_and_retains_last_known_good(self):
        self.scan({"typo.example": POSITIVE})
        seen = self.domain()["last_seen"]
        self.scan({"typo.example": NEGATIVE})
        run = self.scan({"typo.example": UNKNOWN})
        self.assertEqual(run["status"], "partial")
        self.assertEqual(self.domain()["missing_count"], 0)
        self.assertEqual(self.domain()["records"], POSITIVE["records"])
        self.assertEqual(self.domain()["last_seen"], seen)
        self.assertEqual(self.domain()["last_error"], "DNS timeout")
        self.assertEqual(self.scan({"typo.example": NEGATIVE})["events"], [])
        self.assertEqual(self.scan({"typo.example": POSITIVE})["events"], [])
        self.assertIsNone(self.domain()["last_error"])

    def test_unchecked_domain_breaks_negative_streak(self):
        self.scan({"typo.example": POSITIVE})
        self.scan({"typo.example": NEGATIVE})
        self.scan({})
        self.assertEqual(self.scan({"typo.example": NEGATIVE})["events"], [])
        self.assertEqual(self.domain()["missing_count"], 1)

    def test_unknown_after_confirmed_missing_does_not_create_second_missing_event(self):
        self.scan({"typo.example": POSITIVE})
        self.scan({"typo.example": NEGATIVE})
        self.scan({"typo.example": NEGATIVE})
        self.scan({"typo.example": UNKNOWN})
        self.assertEqual(self.domain()["status"], "missing")
        self.assertEqual(self.scan({"typo.example": NEGATIVE})["events"], [])
        self.assertEqual(self.scan({"typo.example": POSITIVE})["events"][0]["kind"], "reappeared")

    def test_rrset_order_duplicates_ttl_and_owner_case_do_not_produce_change(self):
        self.scan({"TYPO.Example.": {"status": "resolved", "records": [["A", "192.0.2.1"], ["MX", "10 MAIL.Example."]]}})
        unchanged = self.scan({"typo.example": {"status": "resolved", "records": [
            {"type": "mx", "value": "10 mail.example", "ttl": 1},
            ["A", "192.0.2.1"], ["A", "192.0.2.1"]]}})
        self.assertEqual(unchanged["events"], [])
        changed = self.scan({"typo.example": {"status": "resolved", "records": [["A", "192.0.2.2"]]}})
        self.assertEqual(changed["events"][0]["kind"], "records_changed")

    def test_later_first_resolution_is_observation_not_registration(self):
        self.scan({"typo.example": POSITIVE})
        run = self.scan({"typo.example": POSITIVE, "new.example": POSITIVE})
        self.assertEqual([e["kind"] for e in run["events"]], ["newly_observed"])
        self.assertIn("does not establish a registration date", run["events"][0]["detail"])

    def test_never_resolved_domain_does_not_generate_missing_event(self):
        self.scan({"typo.example": NEGATIVE})
        self.assertEqual(self.scan({"typo.example": NEGATIVE})["events"], [])
        self.assertEqual(self.scan({"typo.example": POSITIVE})["events"][0]["kind"], "newly_observed")

    def test_failed_run_preserves_state_inventory_and_history(self):
        accepted = self.scan({"typo.example": POSITIVE})
        state, inventory = self.domain(), self.store.inventory(self.project_id)
        pending = self.store.start_run(self.project_id)
        failed = self.store.fail_run(pending["id"], "generator failed")
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(self.domain(), state)
        self.assertEqual(self.store.inventory(self.project_id), inventory)
        self.assertEqual(self.scan({"typo.example": POSITIVE})["events"], [])
        self.assertEqual(self.store.list_runs(self.project_id)[-1]["id"], accepted["id"])

    def test_failed_scan_between_negative_checks_breaks_confirmation_sequence(self):
        self.scan({"typo.example": POSITIVE})
        self.scan({"typo.example": NEGATIVE})
        previous = self.domain()
        failed = self.store.start_run(self.project_id)
        self.store.fail_run(failed["id"], "scan crashed")
        self.assertEqual(self.domain(), previous)
        next_run = self.scan({"typo.example": NEGATIVE})
        self.assertEqual(next_run["events"], [])
        self.assertEqual(self.domain()["missing_count"], 1)

    def test_rejects_invalid_observation_atomically(self):
        self.scan({"typo.example": POSITIVE})
        previous = self.domain()
        pending = self.store.start_run(self.project_id)
        with self.assertRaises(ValueError):
            self.store.finish_run(pending["id"], seeds=["new.example"], candidates=["new.example"],
                                  observations={"outside.example": POSITIVE}, source_status=SUCCESS)
        self.assertEqual(self.domain(), previous)
        self.assertNotIn("new.example", self.store.inventory(self.project_id)["seeds"])
        self.assertNotIn("new.example", self.store.inventory(self.project_id)["candidates"])
        self.store.fail_run(pending["id"], "invalid payload")

    def test_skipped_optional_source_does_not_mark_scan_partial(self):
        run = self.scan({"typo.example": POSITIVE}, sources={"subfinder": {"status": "skipped"}})
        self.assertEqual(run["status"], "completed")

    def test_partial_source_keeps_observations_and_marks_scan_partial(self):
        run = self.scan({"typo.example": POSITIVE}, sources={"subfinder": {"status": "partial", "error": "quota exceeded"}})
        self.assertEqual(run["status"], "partial")
        self.assertEqual(self.domain()["records"], POSITIVE["records"])
        self.assertEqual(run["source_status"]["subfinder"]["error"], "quota exceeded")

    def test_equivalent_ipv6_record_formats_do_not_generate_change(self):
        self.scan({"typo.example": {"status": "resolved", "records": [["AAAA", "2001:0db8:0:0:0:0:0:1"]]}})
        run = self.scan({"typo.example": {"status": "resolved", "records": [["AAAA", "2001:db8::1"]]}})
        self.assertEqual(run["events"], [])
        self.assertEqual(self.domain()["records"], [["AAAA", "2001:db8::1"]])

    def test_concurrent_start_has_exactly_one_winner(self):
        barrier = threading.Barrier(2)

        def start():
            barrier.wait(timeout=5)
            try:
                return self.store.start_run(self.project_id)["id"]
            except RuntimeError:
                return None

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: start(), range(2)))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(len(self.store.list_runs(self.project_id)), 1)

    def test_startup_recovers_interrupted_scan_and_allows_next_run(self):
        self.scan({"typo.example": POSITIVE})
        previous = self.domain()
        interrupted = self.store.start_run(self.project_id)
        reopened = Store(self.temp.name)
        self.assertEqual(reopened.recover_interrupted_runs(), 1)
        self.assertEqual(reopened.recover_interrupted_runs(), 0)
        self.assertEqual(self.store.get_run(interrupted["id"])["status"], "failed")
        self.assertEqual(self.domain(), previous)
        self.assertEqual(self.scan({"typo.example": POSITIVE})["events"], [])

    def test_comparison_scope_persists_across_restart_and_key_order(self):
        scope = {"nameservers": ["192.0.2.53"], "query_types": ["A", "AAAA"], "missing_threshold": 2}
        self.assertIsNone(self.project["comparison_scope"])
        self.store.bind_comparison_scope(self.project_id, scope)
        self.scan({"typo.example": POSITIVE})
        reopened = Store(self.temp.name)
        self.assertEqual(reopened.get_project(self.project_id)["comparison_scope"], scope)
        reordered = dict(reversed(list(scope.items())))
        self.assertEqual(reopened.bind_comparison_scope(self.project_id, reordered)["comparison_scope"], scope)

    def test_changed_comparison_scope_rejected_without_state_or_history_mutation(self):
        scope = {"nameservers": ["192.0.2.53"], "query_types": ["A"], "missing_threshold": 2}
        self.store.bind_comparison_scope(self.project_id, scope)
        self.scan({"typo.example": POSITIVE})
        state, inventory, runs = self.domain(), self.store.inventory(self.project_id), self.store.list_runs(self.project_id)
        for key, value in (("nameservers", ["198.51.100.53"]), ("query_types", ["A", "MX"]), ("missing_threshold", 3)):
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, "DNS comparison settings changed"):
                self.store.bind_comparison_scope(self.project_id, {**scope, key: value})
            self.assertEqual(self.store.get_project(self.project_id)["comparison_scope"], scope)
            self.assertEqual(self.domain(), state)
            self.assertEqual(self.store.inventory(self.project_id), inventory)
            self.assertEqual(self.store.list_runs(self.project_id), runs)

    def test_comparison_scope_can_be_fixed_until_informative_baseline(self):
        old = {"nameservers": ["192.0.2.53"], "query_types": ["A"], "missing_threshold": 2}
        fixed = {**old, "nameservers": ["198.51.100.53"]}
        self.store.bind_comparison_scope(self.project_id, old)
        self.scan({"typo.example": UNKNOWN})
        self.store.bind_comparison_scope(self.project_id, fixed)
        self.assertEqual(self.store.get_project(self.project_id)["comparison_scope"], fixed)
        baseline = self.scan({"typo.example": POSITIVE})
        self.assertTrue(baseline["is_baseline"])
        with self.assertRaises(RuntimeError):
            self.store.bind_comparison_scope(self.project_id, old)

    def test_comparison_scope_column_migrates_existing_database_once(self):
        legacy_dir = Path(self.temp.name) / "legacy"
        legacy_dir.mkdir()
        with closing(sqlite3.connect(legacy_dir / "monitor.sqlite3")) as db, db:
            db.execute("CREATE TABLE projects(id TEXT PRIMARY KEY,name TEXT NOT NULL,roots_json TEXT NOT NULL,created_at TEXT NOT NULL,baseline_run_id TEXT)")
            db.execute("INSERT INTO projects VALUES(?,?,?,?,?)", (self.project_id, "Legacy", '["example.com"]', "2020-01-01T00:00:00Z", "legacy-baseline"))
        migrated = Store(legacy_dir)
        self.assertIsNone(migrated.get_project(self.project_id)["comparison_scope"])
        scope = {"nameservers": ["192.0.2.53"], "query_types": ["A"], "missing_threshold": 2}
        migrated.bind_comparison_scope(self.project_id, scope)
        self.assertEqual(Store(legacy_dir).get_project(self.project_id)["comparison_scope"], scope)
        self.assertEqual(migrated.get_project(self.project_id)["name"], "Legacy")
        self.assertIsNone(migrated.get_project(self.project_id)["schedule_interval_hours"])
        self.assertIsNone(migrated.get_project(self.project_id)["schedule_next_run_at"])

    def test_domain_counts_and_filtered_pagination(self):
        self.scan({"alpha.example": POSITIVE, "beta.example": UNKNOWN, "gamma.example": POSITIVE})
        self.assertEqual(self.store.domain_counts(self.project_id),
                         {"total": 3, "resolved": 2, "unknown": 1, "missing": 0, "pending_missing": 0, "likely_parked": 0})
        page = self.store.query_domains(self.project_id, query="EXAMPLE", limit=1, offset=1)
        self.assertEqual(page["total"], 3)
        self.assertEqual([row["domain"] for row in page["items"]], ["beta.example"])
        filtered = self.store.query_domains(self.project_id, query="beta", status="unknown")
        self.assertEqual(filtered["total"], 1)
        self.assertEqual(filtered["items"][0]["domain"], "beta.example")
        self.assertEqual(self.store.query_domains(self.project_id, query="beta", status="resolved")["total"], 0)
        self.assertEqual(self.store.query_domains(self.project_id, offset=100)["items"], [])

    def test_domain_search_treats_sql_wildcards_as_literal_text(self):
        self.scan({"alpha.example": POSITIVE})
        for query in ("%", "_", "\\", "' OR 1=1 --"):
            with self.subTest(query=query):
                self.assertEqual(self.store.query_domains(self.project_id, query=query), {"items": [], "total": 0})

    def test_run_summaries_bound_history_and_skip_events(self):
        self.scan({"typo.example": POSITIVE})
        latest = self.scan({"typo.example": {"status": "resolved", "records": [["A", "192.0.2.2"]]}})
        self.assertTrue(latest["events"])
        summaries = self.store.list_runs(self.project_id, limit=1, include_events=False)
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["id"], latest["id"])
        self.assertEqual(summaries[0]["events"], [])
        self.assertEqual(summaries[0]["counts"]["events"], 1)
        self.assertEqual(self.store.get_project(self.project_id)["last_run"]["events"], [])
        self.assertEqual(self.store.list_projects()[0]["last_run"]["events"], [])
        self.assertEqual(self.store.get_run(latest["id"])["events"], latest["events"])

    def test_provenance_unions_sources_and_survives_missing_discovery_and_restart(self):
        self.scan({"typo.example": POSITIVE}, seeds=["example.com", "portal.example.com"],
                  provenance={"TYPO.Example.": ["PORTAL.example.com."]})
        self.scan({"typo.example": POSITIVE}, provenance={"typo.example": ["example.com"]})
        self.assertEqual(self.domain()["sources"], ["example.com", "portal.example.com"])
        reopened = Store(self.temp.name)
        row = reopened.query_domains(self.project_id, seed="portal.example.com")["items"][0]
        self.assertEqual(row["sources"], ["example.com", "portal.example.com"])
        self.assertEqual(reopened.source_groups(self.project_id),
                         [{"seed": "example.com", "total": 1}, {"seed": "portal.example.com", "total": 1}])
        self.assertFalse(row["is_seed"])

    def test_seed_domains_excluded_and_unattributed_candidates_filterable(self):
        self.scan({"example.com": POSITIVE, "portal.example.com": POSITIVE,
                   "root-typo.example": POSITIVE, "sub-typo.example": POSITIVE, "legacy.example": POSITIVE},
                  seeds=["example.com", "portal.example.com"],
                  provenance={"root-typo.example": ["example.com"], "sub-typo.example": ["portal.example.com"]})
        all_rows = self.store.get_domains(self.project_id)
        self.assertEqual({row["domain"] for row in all_rows if row["is_seed"]}, {"example.com", "portal.example.com"})
        findings = self.store.query_domains(self.project_id, status="resolved", include_seeds=False)
        self.assertEqual(findings["total"], 3)
        self.assertFalse(any(row["is_seed"] for row in findings["items"]))
        self.assertEqual(self.store.query_domains(self.project_id, seed="__unattributed__", include_seeds=False)["items"][0]["domain"], "legacy.example")
        self.assertEqual(self.store.source_groups(self.project_id), [
            {"seed": "__unattributed__", "total": 1}, {"seed": "example.com", "total": 1},
            {"seed": "portal.example.com", "total": 1}])
        self.assertEqual(self.store.source_groups(self.project_id, query="sub-typo"), [{"seed": "portal.example.com", "total": 1}])

    def test_parking_filter_is_optional_and_evidence_returned_in_both_domain_apis(self):
        parking = {"status": "likely_parked", "provider": "Fixture Parking", "evidence": ["CNAME points to known parking host"]}
        self.scan({"parked.example": {**POSITIVE, "parking": parking}, "active.example": POSITIVE},
                  provenance={"parked.example": ["example.com"], "active.example": ["example.com"]})
        all_findings = self.store.query_domains(self.project_id, status="resolved", include_seeds=False)
        self.assertEqual(all_findings["total"], 2)
        visible = self.store.query_domains(self.project_id, status="resolved", include_seeds=False, hide_parked=True)
        self.assertEqual([row["domain"] for row in visible["items"]], ["active.example"])
        state = self.domain("parked.example")
        self.assertEqual({key: state["parking"][key] for key in parking}, parking)
        self.assertIsNotNone(state["parking"]["checked_at"])
        self.assertEqual(self.store.query_domains(self.project_id, query="parked")["items"][0], state)
        self.assertEqual(self.store.domain_counts(self.project_id)["likely_parked"], 1)
        self.assertEqual(self.store.source_groups(self.project_id, hide_parked=True), [{"seed": "example.com", "total": 1}])
        export = self.store.export_domains(self.project_id, status="resolved", include_seeds=False,
                                           hide_parked=True, seed="example.com", query="active")
        self.assertEqual(export, visible["items"])

    def test_negative_and_unknown_dns_checks_clear_stale_parking_evidence(self):
        parked = {**POSITIVE, "parking": {"status": "likely_parked", "provider": "Fixture", "evidence": ["Known host"]}}
        for observation in (NEGATIVE, UNKNOWN):
            with self.subTest(status=observation["status"]):
                self.scan({"typo.example": parked})
                self.scan({"typo.example": observation})
                state = self.domain()
                self.assertEqual(state["parking"]["status"], "unknown")
                self.assertIsNone(state["parking"]["provider"])
                self.assertEqual(state["parking"]["evidence"], [])
                self.assertEqual(self.store.domain_counts(self.project_id)["likely_parked"], 0)

    def test_missing_parking_classifier_does_not_reuse_old_positive_evidence(self):
        self.scan({"typo.example": {**POSITIVE, "parking": {"status": "likely_parked", "provider": "Fixture", "evidence": []}}})
        self.scan({"typo.example": POSITIVE})
        self.assertEqual(self.domain()["parking"]["status"], "unknown")
        self.assertEqual(self.store.query_domains(self.project_id, status="resolved", hide_parked=True)["total"], 1)

    def test_unresolved_candidate_appears_when_later_scan_resolves_with_retained_sources(self):
        self.scan({"active.example": POSITIVE, "typo.example": NEGATIVE},
                  seeds=["example.com", "portal.example.com"],
                  provenance={"active.example": ["example.com"], "typo.example": ["portal.example.com"]})
        findings = self.store.query_domains(self.project_id, status="resolved", include_seeds=False)
        self.assertEqual([row["domain"] for row in findings["items"]], ["active.example"])
        run = self.scan({"active.example": POSITIVE, "typo.example": POSITIVE})
        self.assertEqual([event["kind"] for event in run["events"]], ["newly_observed"])
        findings = self.store.query_domains(self.project_id, status="resolved", include_seeds=False, seed="portal.example.com")
        self.assertEqual(findings["total"], 1)
        self.assertEqual(findings["items"][0]["sources"], ["portal.example.com"])
        self.assertEqual(findings["items"][0]["domain"], "typo.example")

    def test_invalid_provenance_rolls_back_associations_and_inventory(self):
        self.scan({"typo.example": POSITIVE}, provenance={"typo.example": ["example.com"]})
        previous = self.domain()
        pending = self.store.start_run(self.project_id)
        with self.assertRaisesRegex(ValueError, "Provenance"):
            self.store.finish_run(pending["id"], seeds=["new.example"], candidates=["new.example"],
                                  observations={"new.example": POSITIVE}, source_status=SUCCESS,
                                  provenance={"new.example": ["unknown-seed.example"]})
        self.assertEqual(self.domain(), previous)
        self.assertNotIn("new.example", self.store.inventory(self.project_id)["seeds"])
        self.store.fail_run(pending["id"], "invalid provenance")

    def test_http_and_https_captures_roundtrip_with_run_and_project_scope(self):
        http = {**CAPTURE, "scheme": "http", "url": "http://typo.example", "relative_path": "screenshots/http-typo.jpg"}
        run = self.scan({"typo.example": POSITIVE}, screenshots={"TYPO.Example.": [http, CAPTURE]})
        self.assertEqual(run["counts"]["screenshots_captured"], 2)
        self.assertEqual(run["counts"]["screenshots_failed"], 0)
        self.assertEqual(run["counts"]["screenshots_total"], 2)
        self.assertEqual([capture["scheme"] for capture in self.domain()["screenshots"]], ["http", "https"])
        expected = {**CAPTURE, "run_id": run["id"], "project_id": self.project_id, "domain": "typo.example", "visual": {}, "analysis": {}}
        self.assertEqual(self.store.get_capture(run["id"], "TYPO.Example.", "https"), expected)
        self.assertEqual(Store(self.temp.name).get_capture(run["id"], "typo.example", "https"), expected)
        self.assertEqual(self.store.get_domain(self.project_id, "TYPO.Example."), self.domain())
        self.assertIsNone(self.store.get_domain(self.project_id, "absent.example"))
        self.assertIsNone(self.store.get_capture(run["id"], "other.example", "https"))
        self.assertIsNone(self.store.get_capture(run["id"], "typo.example", "ftp"))

    def test_latest_failed_capture_keeps_explicit_previous_image_and_does_not_reject_dns(self):
        http = {**CAPTURE, "scheme": "http", "url": "http://typo.example", "relative_path": "screenshots/http-typo.jpeg"}
        first = self.scan({"typo.example": POSITIVE}, screenshots={"typo.example": [CAPTURE, http]})
        failed = {**CAPTURE, "status": "failed", "relative_path": None, "title": None, "http_status": None,
                  "error": "Navigation timed out", "captured_at": "2026-10-16T13:00:00Z"}
        changed = {"status": "resolved", "records": [["A", "192.0.2.2"]]}
        second = self.scan({"typo.example": changed}, screenshots={"typo.example": [failed]},
                           sources={**SUCCESS, "screenshots": {"status": "partial", "error": "One navigation failed"}})
        self.assertEqual(second["status"], "partial")
        self.assertEqual(second["counts"]["screenshots_failed"], 1)
        self.assertEqual(second["events"][0]["kind"], "records_changed")
        self.assertEqual(self.domain()["records"], changed["records"])
        latest = self.domain()["screenshots"]
        self.assertEqual(latest[0]["run_id"], first["id"])
        self.assertEqual(latest[1]["run_id"], second["id"])
        self.assertEqual(latest[1]["status"], "failed")
        self.assertIsNone(latest[1]["relative_path"])
        self.assertEqual(latest[1]["previous_capture"]["run_id"], first["id"])
        self.assertEqual(latest[1]["previous_capture"]["captured_at"], CAPTURE["captured_at"])
        self.assertEqual(latest[1]["previous_capture"]["relative_path"], CAPTURE["relative_path"])
        self.assertEqual(len(self.store.list_captures(self.project_id, "typo.example")), 3)
        self.assertEqual(self.store.list_captures(self.project_id, "typo.example", limit=1)[0]["run_id"], second["id"])
        self.scan({"typo.example": changed})
        self.assertEqual(self.domain()["screenshots"], latest)

    def test_unavailable_and_skipped_attempts_preserved_as_status_not_fake_images(self):
        attempts = [{**CAPTURE, "scheme": scheme, "url": f"{scheme}://typo.example", "status": status,
                     "relative_path": None, "title": None, "http_status": None, "error": "Tool unavailable"}
                    for scheme, status in (("http", "unavailable"), ("https", "skipped"))]
        run = self.scan({"typo.example": POSITIVE}, screenshots={"typo.example": attempts})
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["counts"]["screenshots_unavailable"], 1)
        self.assertEqual(run["counts"]["screenshots_skipped"], 1)
        self.assertTrue(all(capture["relative_path"] is None for capture in self.domain()["screenshots"]))

    def test_capture_paths_and_metadata_validation_roll_back_without_changing_dns(self):
        self.scan({"typo.example": POSITIVE})
        previous = self.domain()
        invalid = [{**CAPTURE, "relative_path": path} for path in (
            "/tmp/page.png", "../page.png", "captures/../../page.jpg", "C:/page.png", "C:page.png",
            "screenshots\\page.png", "page.svg", "page.html", "page.png\x00", None)]
        invalid.extend([{**CAPTURE, "status": "failed"}, {**CAPTURE, "url": "https://outside.example"},
                        {**CAPTURE, "url": "http://typo.example"}, {**CAPTURE, "url": "https://user:pass@typo.example"},
                        {**CAPTURE, "captured_at": "2026-10-16T13:00:00"}, {**CAPTURE, "http_status": True}])
        for attempt in invalid:
            with self.subTest(attempt=attempt):
                pending = self.store.start_run(self.project_id)
                with self.assertRaises(ValueError):
                    self.store.finish_run(pending["id"], seeds=["example.com"], candidates=["typo.example"],
                        observations={"typo.example": POSITIVE}, source_status=SUCCESS, screenshots={"typo.example": [attempt]})
                self.assertEqual(self.domain(), previous)
                self.assertEqual(self.store.list_captures(self.project_id, "typo.example"), [])
                self.store.fail_run(pending["id"], "invalid capture")

    def test_capture_candidate_scope_validation_is_atomic(self):
        self.scan({"typo.example": POSITIVE})
        pending = self.store.start_run(self.project_id)
        outside = {**CAPTURE, "url": "https://outside.example"}
        with self.assertRaisesRegex(ValueError, "Screenshots must belong"):
            self.store.finish_run(pending["id"], seeds=["new.example"], candidates=["typo.example"],
                observations={"typo.example": POSITIVE}, source_status=SUCCESS, screenshots={"outside.example": [outside]})
        self.assertNotIn("new.example", self.store.inventory(self.project_id)["seeds"])
        self.assertIsNone(self.store.get_capture(pending["id"], "outside.example", "https"))
        self.store.fail_run(pending["id"], "outside scope")

    def test_capture_history_does_not_leak_between_projects_with_same_domain(self):
        first = self.scan({"typo.example": POSITIVE}, screenshots={"typo.example": [CAPTURE]})
        other = self.store.create_project("Separate", ["example.com"])
        run = self.store.start_run(other["id"])
        self.store.finish_run(run["id"], seeds=["example.com"], candidates=["typo.example"],
            observations={"typo.example": POSITIVE}, source_status=SUCCESS,
            screenshots={"typo.example": [{**CAPTURE, "title": "Other project"}]})
        self.assertEqual([capture["run_id"] for capture in self.store.list_captures(self.project_id, "typo.example")], [first["id"]])
        self.assertEqual(self.store.get_domain(other["id"], "typo.example")["screenshots"][0]["title"], "Other project")

    def test_generation_cache_is_durable_per_signature_and_project(self):
        signature = "ail:1.2.3/settings:all"
        self.assertEqual(self.store.generation_cache(self.project_id, signature), set())
        self.scan({"typo.example": POSITIVE}, provenance={"typo.example": ["example.com"]},
                  generation={"signature": signature, "seeds": ["EXAMPLE.com.", "example.com"]})
        reopened = Store(self.temp.name)
        self.assertEqual(reopened.generation_cache(self.project_id, signature), {"example.com"})
        self.assertEqual(reopened.get_domain(self.project_id, "typo.example")["sources"], ["example.com"])
        self.assertEqual(reopened.generation_cache(self.project_id, "ail:1.2.4/settings:all"), set())
        self.assertEqual(reopened.generation_cache(self.project_id, "ail:1.2.3/settings:subset"), set())
        other = reopened.create_project("Separate", ["example.com"])
        self.assertEqual(reopened.generation_cache(other["id"], signature), set())

    def test_generation_markers_accumulate_only_successfully_accepted_new_seeds(self):
        signature = "generator-v1"
        self.scan({"typo.example": POSITIVE}, generation={"signature": signature, "seeds": ["example.com"]})
        self.scan({"typo.example": POSITIVE, "portal-typo.example": POSITIVE},
                  seeds=["example.com", "portal.example.com"],
                  provenance={"portal-typo.example": ["portal.example.com"]},
                  generation={"signature": signature, "seeds": ["portal.example.com"]})
        # A later discovery sample can omit a seed without discarding its cache.
        self.scan({"typo.example": POSITIVE, "portal-typo.example": POSITIVE})
        self.assertEqual(self.store.generation_cache(self.project_id, signature), {"example.com", "portal.example.com"})
        self.assertEqual(self.domain("portal-typo.example")["sources"], ["portal.example.com"])

    def test_partial_dns_run_retains_successful_generation_without_requiring_dns_baseline(self):
        run = self.scan({"typo.example": UNKNOWN},
                        sources={"generator": {"status": "ok"}, "dns": {"status": "partial"}},
                        generation={"signature": "generator-v1", "seeds": ["example.com"]})
        self.assertEqual(run["status"], "partial")
        self.assertFalse(run["is_baseline"])
        self.assertEqual(self.store.generation_cache(self.project_id, "generator-v1"), {"example.com"})

    def test_existing_inventory_does_not_fabricate_generation_markers(self):
        self.scan({"typo.example": POSITIVE})
        self.assertEqual(Store(self.temp.name).generation_cache(self.project_id, "generator-v1"), set())
        pending = self.store.start_run(self.project_id)
        self.store.fail_run(pending["id"], "Cancelled after permutation generation")
        self.assertEqual(self.store.generation_cache(self.project_id, "generator-v1"), set())

    def test_late_database_failure_rolls_back_generation_inventory_and_provenance_together(self):
        self.scan({"typo.example": POSITIVE}, generation={"signature": "generator-v1", "seeds": ["example.com"]})
        previous_inventory = self.store.inventory(self.project_id)
        previous_domains = self.store.get_domains(self.project_id)
        pending = self.store.start_run(self.project_id)
        with self.store._connection(write=True) as db:
            db.execute("""CREATE TRIGGER reject_finish BEFORE UPDATE OF status ON runs
                WHEN NEW.status IN ('completed','partial') BEGIN SELECT RAISE(ABORT,'fixture write failure'); END""")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "fixture write failure"):
            self.store.finish_run(pending["id"], seeds=["portal.example.com"], candidates=["portal-typo.example"],
                observations={"typo.example": POSITIVE, "portal-typo.example": POSITIVE}, source_status=SUCCESS,
                provenance={"portal-typo.example": ["portal.example.com"]},
                generation={"signature": "generator-v1", "seeds": ["portal.example.com"]})
        self.assertEqual(self.store.generation_cache(self.project_id, "generator-v1"), {"example.com"})
        self.assertEqual(self.store.inventory(self.project_id), previous_inventory)
        self.assertEqual(self.store.get_domains(self.project_id), previous_domains)
        self.assertEqual(self.store.get_run(pending["id"])["status"], "running")
        with self.store._connection(write=True) as db:
            db.execute("DROP TRIGGER reject_finish")
        self.store.fail_run(pending["id"], "Acceptance failed")

    def test_invalid_generation_seed_scope_rolls_back_new_inventory(self):
        pending = self.store.start_run(self.project_id)
        with self.assertRaisesRegex(ValueError, "seed inventory"):
            self.store.finish_run(pending["id"], seeds=["portal.example.com"], candidates=["typo.example"],
                observations={"typo.example": POSITIVE}, source_status=SUCCESS,
                generation={"signature": "generator-v1", "seeds": ["outside.example"]})
        self.assertEqual(self.store.inventory(self.project_id), {"seeds": ["example.com"], "candidates": []})
        self.assertEqual(self.store.generation_cache(self.project_id, "generator-v1"), set())
        self.store.fail_run(pending["id"], "Invalid generation scope")

    def test_generation_metadata_validation_does_not_accept_malformed_cache_keys(self):
        for generation in ([], {}, {"signature": "", "seeds": []}, {"signature": "  ", "seeds": []},
                           {"signature": "generator-v1", "seeds": "example.com"},
                           {"signature": "generator-v1", "seeds": ["https://example.com"]}):
            with self.subTest(generation=generation):
                pending = self.store.start_run(self.project_id)
                with self.assertRaises(ValueError):
                    self.store.finish_run(pending["id"], seeds=["example.com"], candidates=["typo.example"],
                        observations={"typo.example": POSITIVE}, source_status=SUCCESS, generation=generation)
                self.assertEqual(self.store.generation_cache(self.project_id, "generator-v1"), set())
                self.store.fail_run(pending["id"], "Invalid generation metadata")

    def test_cancelled_scan_preserves_accepted_state_cache_and_breaks_negative_sequence(self):
        self.scan({"typo.example": POSITIVE}, generation={"signature": "generator-v1", "seeds": ["example.com"]})
        self.scan({"typo.example": NEGATIVE})
        previous_state = self.store.get_domains(self.project_id)
        previous_inventory = self.store.inventory(self.project_id)
        pending = self.store.start_run(self.project_id)
        cancelled = self.store.cancel_run(pending["id"])
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(cancelled["error"], "Scan cancelled by user.")
        self.assertIsNotNone(cancelled["finished_at"])
        self.assertEqual(self.store.get_domains(self.project_id), previous_state)
        self.assertEqual(self.store.inventory(self.project_id), previous_inventory)
        self.assertEqual(self.store.generation_cache(self.project_id, "generator-v1"), {"example.com"})
        with self.assertRaisesRegex(ValueError, "already finished"):
            self.store.finish_run(pending["id"], seeds=["portal.example.com"], candidates=["new.example"],
                observations={"new.example": POSITIVE}, source_status=SUCCESS,
                generation={"signature": "generator-v1", "seeds": ["portal.example.com"]})
        self.assertEqual(self.store.inventory(self.project_id), previous_inventory)
        self.assertEqual(self.store.get_domains(self.project_id), previous_state)
        self.assertEqual(self.store.generation_cache(self.project_id, "generator-v1"), {"example.com"})
        run = self.scan({"typo.example": NEGATIVE})
        self.assertEqual(run["events"], [])
        self.assertEqual(self.domain()["missing_count"], 1)
        self.assertEqual(self.scan({"typo.example": NEGATIVE})["events"][0]["kind"], "missing_confirmed")

    def test_cancellation_is_idempotent_and_cannot_overwrite_terminal_run(self):
        accepted = self.scan({"typo.example": POSITIVE})
        self.assertEqual(self.store.cancel_run(accepted["id"]), accepted)
        with self.assertRaises(KeyError):
            self.store.cancel_run("missing")
        pending = self.store.start_run(self.project_id)
        cancelled = self.store.cancel_run(pending["id"], "Stopped by the client")
        self.assertEqual(self.store.get_run(pending["id"])["error"], "Stopped by the client")
        self.assertEqual(self.store.cancel_run(pending["id"]), cancelled)
        replacement = self.store.start_run(self.project_id)
        self.store.fail_run(replacement["id"], "Fixture cleanup")

    def test_default_schedule_inherits_server_setting_and_advance_is_noop(self):
        self.assertIsNone(self.project["schedule_interval_hours"])
        self.assertIsNone(self.project["schedule_next_run_at"])
        self.assertEqual(self.store.advance_schedule(self.project_id), self.project)
        self.assertIsNone(Store(self.temp.name).get_project(self.project_id)["schedule_interval_hours"])
        self.assertEqual(self.store.due_projects("2026-10-17T10:00:00Z"), [])

    def test_project_schedule_deadline_survives_restart_and_advances_from_queue_time(self):
        with patch("typo_monitor.store._now", return_value="2026-10-16T10:00:00.000000+00:00"):
            scheduled = self.store.set_schedule(self.project_id, 24)
        self.assertEqual(scheduled["schedule_interval_hours"], 24)
        self.assertEqual(scheduled["schedule_next_run_at"], "2026-10-17T10:00:00.000000+00:00")
        reopened = Store(self.temp.name)
        self.assertEqual(reopened.get_project(self.project_id)["schedule_next_run_at"], scheduled["schedule_next_run_at"])
        self.assertEqual(reopened.due_projects("2026-10-17T09:59:59Z"), [])
        self.assertEqual([project["id"] for project in reopened.due_projects("2026-10-17T10:00:00Z")], [self.project_id])
        advanced = reopened.advance_schedule(self.project_id, datetime(2026, 10, 17, 10, 5, tzinfo=timezone.utc))
        self.assertEqual(advanced["schedule_next_run_at"], "2026-10-18T10:05:00.000000+00:00")
        self.assertEqual(Store(self.temp.name).get_project(self.project_id)["schedule_next_run_at"], advanced["schedule_next_run_at"])

    def test_each_project_has_independent_schedule_and_off_clears_deadline(self):
        other = self.store.create_project("Other client", ["other.example"])
        with patch("typo_monitor.store._now", return_value="2026-10-16T10:00:00Z"):
            self.store.set_schedule(self.project_id, 1)
            self.store.set_schedule(other["id"], 6)
        self.assertEqual([project["id"] for project in self.store.due_projects("2026-10-16T11:00:00Z")], [self.project_id])
        self.store.advance_schedule(self.project_id, "2026-10-16T11:00:00Z")
        self.assertEqual(self.store.get_project(other["id"])["schedule_next_run_at"], "2026-10-16T16:00:00.000000+00:00")
        disabled = self.store.set_schedule(self.project_id, 0)
        self.assertEqual(disabled["schedule_interval_hours"], 0)
        self.assertIsNone(disabled["schedule_next_run_at"])
        self.assertIsNone(self.store.advance_schedule(self.project_id, "2026-10-17T10:00:00Z")["schedule_next_run_at"])
        self.assertEqual([project["id"] for project in self.store.due_projects("2026-10-17T10:00:00Z")], [other["id"]])

    def test_due_projects_excludes_active_and_simulated_projects(self):
        demo = self.store.create_project("Offline preview", ["demo.example"])
        run = self.store.start_run(demo["id"])
        self.store.finish_run(run["id"], seeds=["demo.example"], candidates=["demo.example"],
                             observations={"demo.example": POSITIVE}, source_status={"demo": {"status": "ok"}})
        with patch("typo_monitor.store._now", return_value="2026-10-16T10:00:00Z"):
            self.store.set_schedule(self.project_id, 1)
            self.store.set_schedule(demo["id"], 1)
        active = self.store.start_run(self.project_id)
        self.assertEqual(self.store.due_projects("2026-10-16T12:00:00Z"), [])
        self.store.cancel_run(active["id"])
        self.assertEqual([project["id"] for project in self.store.due_projects("2026-10-16T12:00:00Z")], [self.project_id])

    def test_invalid_schedule_does_not_change_existing_interval_or_deadline(self):
        with patch("typo_monitor.store._now", return_value="2026-10-16T10:00:00Z"):
            original = self.store.set_schedule(self.project_id, 12)
        for interval in (-1, 0.5, 8761, float("nan"), float("inf"), -float("inf"), True, None, "24", {}, 10 ** 1000):
            with self.subTest(interval=interval), self.assertRaises(ValueError):
                self.store.set_schedule(self.project_id, interval)
            self.assertEqual(self.store.get_project(self.project_id), original)
        for now in ("not-a-date", "2026-10-16T12:00:00", datetime(2026, 10, 16), True):
            with self.subTest(now=now), self.assertRaises(ValueError):
                self.store.advance_schedule(self.project_id, now)
            self.assertEqual(self.store.get_project(self.project_id), original)


if __name__ == "__main__":
    unittest.main()
