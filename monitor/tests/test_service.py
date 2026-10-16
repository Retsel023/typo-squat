import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from typo_monitor.service import MonitorService


class Discoverer:
    executable = "fixture"

    def __init__(self):
        self.calls = 0

    def discover(self, roots, workdir):
        self.calls += 1
        return (["portal.example.com"] if self.calls == 1 else []), {"status": "ok"}


class Generator:
    fail = False

    def generate(self, seeds, workdir):
        if self.fail:
            raise RuntimeError("fixture generation failure")
        return sorted(set(seeds) | {"examp1e.com"}), {"status": "ok"}


class Resolver:
    incomplete = False

    def resolve(self, candidates):
        self.last_candidates = candidates
        observations = {d: {"status": "resolved", "records": [["A", "192.0.2.1"]]} for d in candidates}
        if self.incomplete:
            observations.pop(candidates[0])
        return observations


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.generator, self.resolver = Generator(), Resolver()
        self.service = MonitorService(self.temp.name, generator=self.generator, resolver=self.resolver, discoverer=Discoverer())
        self.project = self.service.create_project("Example", ["example.com"])

    def tearDown(self):
        self.service.close()
        self.temp.cleanup()

    def test_discovery_fluctuates_but_next_scan_checks_same_inventory(self):
        first = self.service.scan_now(self.project["id"])
        first_candidates = self.resolver.last_candidates.copy()
        second = self.service.scan_now(self.project["id"])
        self.assertTrue(first["is_baseline"])
        self.assertEqual(second["status"], "completed")
        self.assertEqual(second["events"], [])
        self.assertEqual(self.resolver.last_candidates, first_candidates)
        self.assertIn("portal.example.com", self.resolver.last_candidates)
        self.assertTrue((Path(self.temp.name) / "runs" / first["id"] / "observations.json").is_file())

    def test_parking_filter_refreshes_without_replacing_dns_history(self):
        class Parking:
            parked = True

            def enrich(self, observations):
                for observation in observations.values():
                    observation["parking"] = {
                        "status": "likely_parked" if self.parked else "not_detected",
                        "provider": "Afternic" if self.parked else None,
                        "evidence": ["Fixture evidence"],
                    }
                return observations
        parking = Parking()
        self.service.parking_classifier = parking
        self.generator.provenance = {"examp1e.com": ["example.com"]}
        self.service.scan_now(self.project["id"])
        self.assertEqual(self.service.store.query_domains(self.project["id"], status="resolved", include_seeds=False)["total"], 1)
        self.assertEqual(self.service.store.query_domains(self.project["id"], status="resolved", include_seeds=False, hide_parked=True)["total"], 0)
        parking.parked = False
        second = self.service.scan_now(self.project["id"])
        self.assertEqual(second["events"], [])
        visible = self.service.store.query_domains(self.project["id"], status="resolved", include_seeds=False, hide_parked=True)
        self.assertEqual(visible["total"], 1)
        self.assertEqual(visible["items"][0]["sources"], ["example.com"])

    def test_generation_failure_preserves_accepted_baseline(self):
        self.service.scan_now(self.project["id"])
        before = self.service.store.get_domains(self.project["id"])
        self.generator.fail = True
        with self.assertLogs("typo_monitor.service", level="ERROR"):
            failed = self.service.scan_now(self.project["id"])
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(before, self.service.store.get_domains(self.project["id"]))

    def test_incomplete_resolver_batch_is_failed_not_a_shrinking_snapshot(self):
        self.service.scan_now(self.project["id"])
        before = self.service.store.get_domains(self.project["id"])
        self.resolver.incomplete = True
        with self.assertLogs("typo_monitor.service", level="ERROR"):
            result = self.service.scan_now(self.project["id"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(before, self.service.store.get_domains(self.project["id"]))

    def test_candidate_limit_fails_without_silent_truncation(self):
        self.service.max_candidates = 1
        with self.assertLogs("typo_monitor.service", level="ERROR"):
            result = self.service.scan_now(self.project["id"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(self.service.store.inventory(self.project["id"])["candidates"], [])

    def test_second_process_cannot_recover_a_live_instances_run(self):
        with self.assertRaisesRegex(RuntimeError, "Another monitor process"):
            MonitorService(self.temp.name)

    def test_resolver_fingerprint_change_after_restart_rejected_before_adapter_calls(self):
        original_scope = {"nameservers": ["192.0.2.53"], "query_types": ["A", "AAAA", "CNAME"], "missing_threshold": 2}
        self.resolver.comparison_scope = lambda: original_scope
        self.service.scan_now(self.project["id"])
        previous_state = self.service.store.get_domains(self.project["id"])
        previous_inventory = self.service.store.inventory(self.project["id"])
        previous_runs = self.service.store.list_runs(self.project["id"])
        discoverer = self.service.discoverer
        self.service.close()
        self.resolver.comparison_scope = lambda: {**original_scope, "nameservers": ["198.51.100.53"]}
        self.service = MonitorService(self.temp.name, generator=self.generator,
                                      resolver=self.resolver, discoverer=discoverer)
        with (patch.object(self.generator, "generate") as generate,
              patch.object(self.resolver, "resolve") as resolve,
              patch.object(discoverer, "discover") as discover):
            with self.assertRaisesRegex(RuntimeError, "DNS comparison settings changed"):
                self.service.scan_now(self.project["id"])
            generate.assert_not_called()
            resolve.assert_not_called()
            discover.assert_not_called()
        self.assertEqual(self.service.store.get_domains(self.project["id"]), previous_state)
        self.assertEqual(self.service.store.inventory(self.project["id"]), previous_inventory)
        self.assertEqual(self.service.store.list_runs(self.project["id"]), previous_runs)
        self.assertEqual(self.service.store.get_project(self.project["id"])["comparison_scope"], original_scope)

    def test_simulated_project_cannot_be_real_scanned_or_call_adapters(self):
        run = self.service.store.start_run(self.project["id"])
        self.service.store.finish_run(
            run["id"], seeds=["example.com"], candidates=["example.com"],
            observations={"example.com": {"status": "resolved", "records": [["A", "192.0.2.1"]]}},
            source_status={"demo": {"status": "ok", "detail": "Offline simulated data"}},
        )
        previous_runs = self.service.store.list_runs(self.project["id"])
        with (patch.object(self.generator, "generate") as generate,
              patch.object(self.resolver, "resolve") as resolve,
              patch.object(self.service.discoverer, "discover") as discover):
            with self.assertRaisesRegex(RuntimeError, "offline simulated project"):
                self.service.scan_now(self.project["id"])
            generate.assert_not_called()
            resolve.assert_not_called()
            discover.assert_not_called()
        self.assertEqual(self.service.store.list_runs(self.project["id"]), previous_runs)
        self.assertIsNone(self.service.store.get_project(self.project["id"])["comparison_scope"])


if __name__ == "__main__":
    unittest.main()
