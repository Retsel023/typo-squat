"""Rolling workers use barriers and fixture values, never live DNS queries."""

from copy import deepcopy
from collections import Counter
import threading
from types import SimpleNamespace
import unittest

import dns.resolver

from typo_monitor.adapters import DnsResolver
from typo_monitor.concurrency import bounded_map
from typo_monitor.domains import normalize_domain
from typo_monitor.parking import ParkingClassifier


NAMES = [f"name{index}.example" for index in range(12)]


def dns_result(domain):
    index = int(domain.split(".")[0].removeprefix("name"))
    status = ("resolved", "nxdomain", "noanswer", "unknown")[index % 4]
    return {"status": status, "records": [["A", f"192.0.2.{index + 1}"]] if status == "resolved" else [],
            "error": domain if status == "unknown" else None}


def parking_result(domain):
    index = int(domain.split(".")[0].removeprefix("name"))
    status = ("likely_parked", "not_detected", "unknown")[index % 3]
    return {"status": status, "provider": "Fixture" if status == "likely_parked" else None,
            "evidence": ["NS evidence for " + domain]}


class Background:
    def __init__(self, function):
        self.result, self.error = None, None

        def run():
            try:
                self.result = function()
            except BaseException as error:
                self.error = error

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def finish(self, testcase):
        self.thread.join(timeout=3)
        testcase.assertFalse(self.thread.is_alive(), "Fixture workers did not finish")


class RollingTests(unittest.TestCase):
    def adapter(self, kind, function, *, workers=2, cancel=None):
        if kind == "dns":
            adapter = DnsResolver(workers=workers)
            adapter.observe = function
            adapter.cancel_event = cancel
            return adapter, lambda: adapter.resolve(NAMES)
        adapter = ParkingClassifier(workers=workers)
        adapter._lookup_ns = function
        adapter.cancel_event = cancel
        observations = {name: {"status": "resolved", "records": [["A", "192.0.2.10"]]} for name in NAMES}
        # The same exact normalized name must be looked up only once per call.
        observations["NAME0.EXAMPLE."] = deepcopy(observations[NAMES[0]])
        observations.update({status + ".example": {"status": status, "records": []}
                             for status in ("nxdomain", "noanswer", "unknown")})
        self.original = observations
        return adapter, lambda: adapter.enrich(observations)

    def test_slow_first_name_does_not_block_refill_and_results_keep_identity(self):
        for kind in ("dns", "parking"):
            with self.subTest(adapter=kind):
                first_started, last_fast_started, release = (threading.Event() for _ in range(3))
                lock = threading.Lock()
                calls, active = [], [0, 0]
                result_for = dns_result if kind == "dns" else parking_result

                def observe(domain):
                    with lock:
                        calls.append(domain)
                        active[0] += 1
                        active[1] = max(active[1], active[0])
                    try:
                        if domain == NAMES[0]:
                            first_started.set()
                            if not release.wait(timeout=3):
                                raise RuntimeError("Slow fixture was not released")
                        if domain == NAMES[-1]:
                            last_fast_started.set()
                        return result_for(domain)
                    finally:
                        with lock:
                            active[0] -= 1

                _, run = self.adapter(kind, observe)
                before = deepcopy(getattr(self, "original", {}))
                background = Background(run)
                try:
                    self.assertTrue(first_started.wait(timeout=1))
                    # Twelve names cross the old 2*4 chunk boundary while the
                    # first query is still blocked, using the other worker.
                    self.assertTrue(last_fast_started.wait(timeout=2), "A slow first query stalled later work")
                    self.assertTrue(background.thread.is_alive())
                    with lock:
                        self.assertEqual(set(calls), set(NAMES))
                        self.assertEqual(len(calls), len(NAMES))
                        self.assertEqual(active[1], 2)
                finally:
                    release.set()
                    background.finish(self)
                self.assertIsNone(background.error)
                if kind == "dns":
                    self.assertEqual(background.result, {name: dns_result(name) for name in NAMES})
                else:
                    self.assertEqual(self.original, before, "Parking enrichment mutated DNS input")
                    self.assertEqual(set(background.result), set(before))
                    for original, row in background.result.items():
                        self.assertEqual(row["status"], before[original]["status"])
                        self.assertEqual(row["records"], before[original]["records"])
                        if row["status"] == "resolved":
                            self.assertEqual(row["parking"], parking_result(normalize_domain(original)))
                        else:
                            self.assertEqual(row["parking"]["status"], "unknown")

    def test_cancel_stops_refill_without_executing_a_queued_inventory(self):
        for kind in ("dns", "parking"):
            with self.subTest(adapter=kind):
                cancel, started = threading.Event(), threading.Event()
                lock, calls = threading.Lock(), []

                def observe(domain):
                    with lock:
                        calls.append(domain)
                        if len(calls) == 2:
                            started.set()
                    if not cancel.wait(timeout=3):
                        raise RuntimeError("Fixture did not receive cancellation")
                    # Return normally: the coordinator must still reject a
                    # cancelled batch and must not refill from these results.
                    return dns_result(domain) if kind == "dns" else parking_result(domain)

                _, run = self.adapter(kind, observe, cancel=cancel)
                background = Background(run)
                try:
                    self.assertTrue(started.wait(timeout=1))
                finally:
                    cancel.set()
                    background.finish(self)
                self.assertIsInstance(background.error, RuntimeError)
                self.assertIn("cancel", str(background.error).lower())
                self.assertIsNone(background.result)
                self.assertCountEqual(calls, NAMES[:2], "Cancellation executed extra queued work")

    def test_worker_error_does_not_drain_the_remaining_inventory(self):
        for kind in ("dns", "parking"):
            with self.subTest(adapter=kind):
                calls = []

                def fail(domain):
                    calls.append(domain)
                    raise ValueError("Fixture worker failed")

                _, run = self.adapter(kind, fail, workers=1)
                with self.assertRaisesRegex(ValueError, "Fixture worker failed"):
                    run()
                self.assertEqual(calls, NAMES[:1])

    def test_cancel_before_start_makes_no_worker_calls(self):
        for kind in ("dns", "parking"):
            with self.subTest(adapter=kind):
                cancel = threading.Event()
                cancel.set()
                calls = []
                _, run = self.adapter(kind, lambda domain: calls.append(domain), cancel=cancel)
                with self.assertRaisesRegex(RuntimeError, "cancel"):
                    run()
                self.assertEqual(calls, [])

    def test_dns_progress_keeps_negative_and_uncertain_counts(self):
        resolver = DnsResolver(workers=2)
        resolver.observe = dns_result
        resolver.run_id = "fixture-run"
        with self.assertLogs("typo_monitor.adapters", level="INFO") as logs:
            result = resolver.resolve(NAMES[:4])
        self.assertEqual(result, {name: dns_result(name) for name in NAMES[:4]})
        self.assertTrue(any("DNS 4/4 checked; 1 resolved, 2 negative, 1 uncertain" in line
                            and "fixture-run" in line for line in logs.output))

    def test_every_name_and_record_type_is_fresh_on_each_batch(self):
        calls, lock = [], threading.Lock()

        class Answer(list):
            def __init__(self):
                super().__init__([SimpleNamespace(to_text=lambda: "192.0.2.10")])
                self.response = SimpleNamespace(answer=[])

        class Resolver:
            def resolve(self, domain, kind, **kwargs):
                with lock:
                    calls.append((domain, kind))
                status = dns_result(domain)["status"]
                if status == "resolved" and kind == "A":
                    return Answer()
                if status == "nxdomain":
                    raise dns.resolver.NXDOMAIN()
                if status == "unknown":
                    raise dns.resolver.LifetimeTimeout()
                raise dns.resolver.NoAnswer()

        resolver = DnsResolver(workers=2, resolver_factory=Resolver)
        for _ in range(2):
            result = resolver.resolve(NAMES[:4])
            self.assertEqual({name: row["status"] for name, row in result.items()},
                             {name: dns_result(name)["status"] for name in NAMES[:4]})
        self.assertEqual(Counter(calls), Counter({(name, kind): 2 for name in NAMES[:4]
                                                 for kind in ("A", "AAAA", "CNAME")}))

    def test_dns_workers_require_integer_bounds_and_finite_timeout(self):
        for workers in (False, True, 0, 129, 1.5, "2", None):
            with self.subTest(workers=workers), self.assertRaises(ValueError):
                DnsResolver(workers=workers)
        for lifetime in (0, -1, float("nan"), float("inf")):
            with self.subTest(lifetime=lifetime), self.assertRaises(ValueError):
                DnsResolver(lifetime=lifetime)


class SubmissionBoundTests(unittest.TestCase):
    def test_submitted_items_are_bounded_before_any_result_finishes(self):
        release, all_started = threading.Event(), threading.Event()
        lock, consumed, calls = threading.Lock(), [], []

        def names():
            for name in NAMES:
                consumed.append(name)
                yield name

        def observe(domain):
            with lock:
                calls.append(domain)
                if len(calls) == 3:
                    all_started.set()
            if not release.wait(timeout=3):
                raise RuntimeError("Fixture was not released")
            return domain + " result"

        background = Background(lambda: dict(bounded_map(observe, names(), workers=3)))
        try:
            self.assertTrue(all_started.wait(timeout=1))
            self.assertEqual(consumed, NAMES[:3], "The iterator was eagerly submitted beyond the worker cap")
        finally:
            release.set()
            background.finish(self)
        self.assertIsNone(background.error)
        self.assertEqual(background.result, {name: name + " result" for name in NAMES})
        self.assertEqual(sorted(calls), sorted(NAMES))

    def test_empty_input_and_single_worker_preserve_every_result(self):
        self.assertEqual(list(bounded_map(lambda value: value, [], workers=2)), [])
        self.assertEqual(dict(bounded_map(lambda value: value * 2, range(10), workers=1)),
                         {value: value * 2 for value in range(10)})


if __name__ == "__main__":
    unittest.main()
