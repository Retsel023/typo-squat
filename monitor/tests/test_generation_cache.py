"""Service regressions for durable generation reuse and fresh observations."""

import json
from pathlib import Path
import tempfile
import unittest

from typo_monitor.service import MonitorService
from typo_monitor.store import Store


class Discovery:
    executable = "fixture"

    def __init__(self):
        self.domains = []
        self.calls = []

    def discover(self, roots, workdir):
        self.calls.append(tuple(roots))
        return list(self.domains), {"status": "ok"}


class Generator:
    """An adapter without a fingerprint must keep its historical behavior."""

    def __init__(self):
        self.calls = []
        self.provenance = {}
        self.fail = False
        self.partial = False
        self.cancel = False

    def generate(self, seeds, workdir):
        self.calls.append(tuple(sorted(seeds)))
        if self.fail:
            raise RuntimeError("Fixture generation failed")
        self.provenance = {f"typo-{seed}": [seed] for seed in seeds}
        if seeds:
            self.provenance["shared-typo.example"] = sorted(seeds)
        if self.cancel:
            self.cancel_event.set()
        return sorted(self.provenance), {"status": "partial" if self.partial else "ok"}


class FingerprintedGenerator(Generator):
    def __init__(self, signature="fixture-generator:v1/options:all"):
        super().__init__()
        self.signature = signature

    def cache_signature(self):
        return self.signature


class Resolver:
    def __init__(self):
        self.calls = []
        self.fail = False
        self.incomplete = False
        self.unknown = False
        self.overrides = {}

    def resolve(self, candidates):
        self.calls.append(tuple(sorted(candidates)))
        if self.fail:
            raise RuntimeError("Fixture DNS failed after generation")
        observations = {
            domain: ({"status": "unknown", "records": [], "error": "Fixture timeout"}
                     if self.unknown else {"status": "resolved", "records": [["A", "192.0.2.1"]]})
            for domain in candidates
        }
        observations.update({domain: dict(observation) for domain, observation in self.overrides.items()
                             if domain in observations})
        if self.incomplete:
            observations.pop(next(iter(observations)))
        return observations


class Parking:
    def __init__(self):
        self.calls = []
        self.parked = True

    def enrich(self, observations):
        self.calls.append(tuple(sorted(observations)))
        for observation in observations.values():
            observation["parking"] = {"status": "likely_parked" if self.parked else "not_detected",
                                      "provider": "Fixture parking" if self.parked else None,
                                      "evidence": ["Fixture observation"]}
        return observations


class Capturer:
    def __init__(self):
        self.calls = []

    def capture(self, domains, workdir):
        self.calls.append(tuple(sorted(domains)))
        attempts = {domain: [{"scheme": scheme, "url": f"{scheme}://{domain}", "status": "skipped",
                              "relative_path": None, "error": "Fixture skips browser work",
                              "captured_at": "2026-10-16T12:00:00Z"}
                             for scheme in ("http", "https")] for domain in domains}
        return attempts, {"status": "skipped", "detail": "Fixture records attempts without image I/O"}


class GenerationCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.services = []
        self.generator = FingerprintedGenerator()
        self.discovery, self.resolver = Discovery(), Resolver()
        self.parking, self.capturer = Parking(), Capturer()
        self.service = self.new_service()
        self.project = self.service.create_project("Example", ["example.com"])

    def tearDown(self):
        for service in reversed(self.services):
            service.close()
        self.temp.cleanup()

    def new_service(self, **overrides):
        options = {"generator": self.generator, "discoverer": self.discovery, "resolver": self.resolver,
                   "parking_classifier": self.parking, "capturer": self.capturer}
        options.update(overrides)
        service = MonitorService(self.temp.name, **options)
        self.services.append(service)
        return service

    def scan(self, project=None):
        return self.service.scan_now((project or self.project)["id"])

    def markers(self, signature=None, project=None):
        return self.service.store.generation_cache((project or self.project)["id"], signature or self.generator.signature)

    def failed_scan(self):
        with self.assertLogs("typo_monitor.service", level="ERROR"):
            result = self.scan()
        self.assertEqual(result["status"], "failed")
        return result

    def test_cache_hit_skips_generation_but_refreshes_dns_parking_and_captures(self):
        self.discovery.domains = ["portal.example.com"]
        first = self.scan()
        inventory = set(self.resolver.calls[-1])
        self.assertEqual(first["status"], "completed")
        self.assertEqual(self.markers(), {"example.com", "portal.example.com"})
        self.discovery.domains = []  # Passive discovery does not reproduce its prior result.
        self.parking.parked = False
        second = self.scan()
        self.assertEqual(second["status"], "completed")
        self.assertEqual(self.generator.calls, [("example.com", "portal.example.com")])
        self.assertEqual(second["source_status"]["generator"]["generated_seeds"], 0)
        self.assertEqual(second["source_status"]["generator"]["reused_seeds"], 2)
        self.assertEqual(second["source_status"]["generator"]["signature"], self.generator.signature)
        self.assertEqual(len(self.discovery.calls), 2)
        self.assertEqual(len(self.resolver.calls), 2)
        self.assertEqual(len(self.parking.calls), 2)
        self.assertEqual(len(self.capturer.calls), 2)
        for calls in (self.resolver.calls, self.parking.calls, self.capturer.calls):
            self.assertEqual(set(calls[-1]), inventory)
        self.assertIn("portal.example.com", inventory)
        self.assertIn("typo-portal.example.com", inventory)
        self.assertEqual(self.service.store.get_domain(self.project["id"], "typo-portal.example.com")["parking"]["status"], "not_detected")
        self.assertEqual(second["events"], [])

    def test_new_seed_alone_is_generated_and_old_candidate_provenance_is_retained(self):
        self.scan()
        old_inventory = set(self.resolver.calls[-1])
        self.discovery.domains = ["portal.example.com"]
        second = self.scan()
        self.assertEqual(second["status"], "completed")
        self.assertEqual(self.generator.calls, [("example.com",), ("portal.example.com",)])
        self.assertEqual(second["source_status"]["generator"]["generated_seeds"], 1)
        self.assertEqual(second["source_status"]["generator"]["reused_seeds"], 1)
        self.assertTrue(old_inventory < set(self.resolver.calls[-1]))
        self.assertEqual(self.markers(), {"example.com", "portal.example.com"})
        shared = self.service.store.get_domain(self.project["id"], "shared-typo.example")
        self.assertEqual(shared["sources"], ["example.com", "portal.example.com"])
        old_typo = self.service.store.get_domain(self.project["id"], "typo-example.com")
        self.assertEqual(old_typo["sources"], ["example.com"])
        provenance = json.loads((Path(self.temp.name) / "runs" / second["id"] / "provenance.json").read_text())
        self.assertNotIn("typo-example.com", provenance)
        self.assertEqual(provenance["typo-portal.example.com"], ["portal.example.com"])

    def test_cached_generation_still_detects_dns_record_changes_and_candidate_activation(self):
        self.resolver.overrides["shared-typo.example"] = {"status": "nxdomain", "records": []}
        self.scan()
        self.resolver.overrides = {
            "typo-example.com": {"status": "resolved", "records": [["A", "192.0.2.2"]]},
            "shared-typo.example": {"status": "resolved", "records": [["A", "192.0.2.3"]]},
        }
        second = self.scan()
        self.assertEqual(second["status"], "completed")
        self.assertEqual(self.generator.calls, [("example.com",)])
        self.assertEqual(self.resolver.calls[0], self.resolver.calls[1])
        changes = {(event["domain"], event["kind"]) for event in second["events"]}
        self.assertIn(("typo-example.com", "records_changed"), changes)
        self.assertIn(("shared-typo.example", "newly_observed"), changes)
        activated = self.service.store.get_domain(self.project["id"], "shared-typo.example")
        self.assertEqual(activated["status"], "resolved")
        self.assertEqual(activated["records"], [["A", "192.0.2.3"]])

    def test_cached_generation_still_requires_fresh_negative_dns_checks(self):
        self.scan()
        self.resolver.overrides["typo-example.com"] = {"status": "nxdomain", "records": []}
        second = self.scan()
        self.assertNotIn("missing_confirmed", [event["kind"] for event in second["events"]])
        self.assertEqual(self.service.store.get_domain(self.project["id"], "typo-example.com")["status"], "pending_missing")
        third = self.scan()
        self.assertIn(("typo-example.com", "missing_confirmed"),
                      {(event["domain"], event["kind"]) for event in third["events"]})
        self.assertEqual(self.generator.calls, [("example.com",)])
        self.assertEqual(len(self.resolver.calls), 3)
        self.assertTrue(all(call == self.resolver.calls[0] for call in self.resolver.calls))

    def test_signature_change_regenerates_roots_and_undiscovered_retained_seeds(self):
        self.discovery.domains = ["portal.example.com"]
        self.scan()
        old_signature = self.generator.signature
        self.discovery.domains = []
        self.generator.signature = "fixture-generator:v2/options:all"
        second = self.scan()
        self.assertEqual(second["status"], "completed")
        self.assertEqual(self.generator.calls, [("example.com", "portal.example.com"), ("example.com", "portal.example.com")])
        self.assertEqual(self.markers(old_signature), {"example.com", "portal.example.com"})
        self.assertEqual(self.markers(), {"example.com", "portal.example.com"})

    def test_markers_survive_service_restart_and_new_adapter_instance(self):
        self.discovery.domains = ["portal.example.com"]
        self.scan()
        inventory = set(self.resolver.calls[-1])
        signature = self.generator.signature
        self.service.close()
        self.generator = FingerprintedGenerator(signature)
        self.discovery, self.resolver = Discovery(), Resolver()
        self.parking, self.capturer = Parking(), Capturer()
        self.service = self.new_service()
        result = self.scan()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(self.generator.calls, [])
        self.assertEqual(set(self.resolver.calls[-1]), inventory)
        self.assertEqual(self.markers(), {"example.com", "portal.example.com"})
        self.assertEqual(Store(self.temp.name).generation_cache(self.project["id"], signature), self.markers())

    def test_adapter_without_signature_stays_uncached(self):
        self.service.close()
        generator = Generator()
        self.service = self.new_service(generator=generator)
        self.scan()
        self.scan()
        self.assertEqual(generator.calls, [("example.com",), ("example.com",)])
        self.assertEqual(self.markers(), set())

    def test_generation_exception_does_not_create_cache_markers(self):
        self.generator.fail = True
        self.failed_scan()
        self.assertEqual(self.markers(), set())
        self.assertEqual(self.service.store.inventory(self.project["id"])["candidates"], [])
        self.generator.fail = False
        self.assertEqual(self.scan()["status"], "completed")
        self.assertEqual(self.generator.calls, [("example.com",), ("example.com",)])
        self.assertEqual(self.markers(), {"example.com"})

    def test_later_dns_failure_does_not_cache_unaccepted_generation(self):
        self.resolver.fail = True
        self.failed_scan()
        self.assertEqual(self.markers(), set())
        self.resolver.fail = False
        self.assertEqual(self.scan()["status"], "completed")
        self.assertEqual(self.generator.calls, [("example.com",), ("example.com",)])

    def test_incomplete_dns_batch_does_not_cache_generated_results(self):
        self.resolver.incomplete = True
        self.failed_scan()
        self.assertEqual(self.markers(), set())
        self.assertEqual(self.service.store.inventory(self.project["id"])["candidates"], [])

    def test_candidate_limit_does_not_commit_markers_or_truncate_inventory(self):
        self.service.max_candidates = 1
        self.failed_scan()
        self.assertEqual(self.markers(), set())
        self.assertEqual(self.service.store.inventory(self.project["id"])["candidates"], [])
        self.service.max_candidates = 100
        self.assertEqual(self.scan()["status"], "completed")
        self.assertEqual(self.generator.calls, [("example.com",), ("example.com",)])
        self.assertIn("shared-typo.example", self.resolver.calls[-1])

    def test_shutdown_after_generation_does_not_commit_cache_markers(self):
        self.generator.cancel = True
        try:
            self.failed_scan()
            self.assertEqual(self.markers(), set())
            self.assertEqual(self.resolver.calls, [])
        finally:
            # Reset the injected cancellation so normal service cleanup can run.
            self.generator.cancel_event.clear()
            self.generator.cancel = False
        self.assertEqual(self.scan()["status"], "completed")
        self.assertEqual(self.generator.calls, [("example.com",), ("example.com",)])

    def test_partial_generation_is_retried_instead_of_becoming_a_cache_hit(self):
        self.generator.partial = True
        first = self.scan()
        self.assertEqual(first["status"], "partial")
        self.assertEqual(self.markers(), set())
        self.generator.partial = False
        second = self.scan()
        self.assertEqual(second["status"], "completed")
        self.assertEqual(self.generator.calls, [("example.com",), ("example.com",)])
        self.assertEqual(self.markers(), {"example.com"})

    def test_successful_generation_is_cached_even_when_dns_results_are_uncertain(self):
        self.resolver.unknown = True
        first = self.scan()
        self.assertEqual(first["status"], "partial")
        self.assertFalse(first["is_baseline"])
        self.assertEqual(self.markers(), {"example.com"})
        self.resolver.unknown = False
        second = self.scan()
        self.assertEqual(second["status"], "completed")
        self.assertTrue(second["is_baseline"])
        self.assertEqual(self.generator.calls, [("example.com",)])
        self.assertEqual(self.resolver.calls[0], self.resolver.calls[1])

    def test_legacy_inventory_without_markers_generates_once_and_keeps_old_candidates(self):
        run = self.service.store.start_run(self.project["id"])
        self.service.store.finish_run(run["id"], seeds=["example.com", "portal.example.com"],
            candidates=["example.com", "portal.example.com", "legacy-typo.example"],
            observations={"legacy-typo.example": {"status": "resolved", "records": [["A", "192.0.2.1"]]}},
            source_status={"legacy": {"status": "skipped"}})
        self.assertEqual(self.markers(), set())
        first = self.scan()
        second = self.scan()
        self.assertEqual(first["status"], "completed")
        self.assertEqual(second["status"], "completed")
        self.assertEqual(self.generator.calls, [("example.com", "portal.example.com")])
        self.assertIn("legacy-typo.example", self.resolver.calls[-1])
        self.assertEqual(self.markers(), {"example.com", "portal.example.com"})

    def test_reused_adapter_cache_hit_does_not_leak_another_projects_provenance(self):
        first = self.scan()
        other = self.service.create_project("Other", ["other.example.org"])
        self.assertEqual(self.markers(project=other), set())
        self.assertEqual(self.scan(other)["status"], "completed")
        self.assertIn("typo-other.example.org", self.generator.provenance)
        cached = self.scan()
        self.assertEqual(cached["status"], "completed")
        self.assertEqual(self.generator.calls, [("example.com",), ("other.example.org",)])
        self.assertEqual(self.markers(), {"example.com"})
        self.assertEqual(self.markers(project=other), {"other.example.org"})
        artifact = Path(self.temp.name) / "runs" / cached["id"] / "provenance.json"
        self.assertEqual(json.loads(artifact.read_text()), {})
        self.assertEqual(self.service.store.get_domain(self.project["id"], "shared-typo.example")["sources"], ["example.com"])
        self.assertEqual(self.service.store.get_domain(other["id"], "shared-typo.example")["sources"], ["other.example.org"])
        self.assertIsNotNone(self.service.store.get_run(first["id"]))


if __name__ == "__main__":
    unittest.main()
