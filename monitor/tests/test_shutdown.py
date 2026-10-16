"""Shutdown regression tests use only fixtures and isolated Python children."""

import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import dns.resolver

from typo_monitor.adapters import DnsResolver, _run_command
from typo_monitor.service import MonitorService


class CooperativeGenerator:
    def __init__(self):
        self.block = False
        self.calls = []
        self.entered = threading.Event()
        self.canceled = threading.Event()
        self.release = threading.Event()

    def generate(self, seeds, workdir):
        self.calls.append(tuple(seeds))
        if self.block:
            self.entered.set()
            if not self.cancel_event.wait(timeout=5):
                raise RuntimeError("Fixture did not receive shutdown cancellation")
            self.canceled.set()
            # Keep the running task occupied while the queued job is canceled.
            if not self.release.wait(timeout=5):
                raise RuntimeError("Fixture shutdown release timed out")
        return list(seeds), {"status": "ok"}


class FixtureResolver:
    def __init__(self):
        self.calls = []

    def resolve(self, candidates):
        self.calls.append(tuple(candidates))
        return {domain: {"status": "resolved", "records": [["A", "192.0.2.10"]]}
                for domain in candidates}


class ShutdownTests(unittest.TestCase):
    def test_close_cancels_running_and_queued_scans_without_changing_baselines(self):
        with tempfile.TemporaryDirectory() as directory:
            generator, resolver = CooperativeGenerator(), FixtureResolver()
            service = MonitorService(directory, discovery=False,
                                     generator=generator, resolver=resolver)
            self.addCleanup(service.close)
            projects = [service.create_project("First", ["example.com"]),
                        service.create_project("Second", ["example.net"])]
            baselines = [service.scan_now(project["id"]) for project in projects]
            before = {project["id"]: (service.store.get_domains(project["id"]),
                                      service.store.inventory(project["id"]))
                      for project in projects}
            self.assertTrue(all(run["is_baseline"] for run in baselines))
            generator.block = True
            running = service.submit_scan(projects[0]["id"])
            self.assertTrue(generator.entered.wait(timeout=2), "Running fixture never began")
            queued = service.submit_scan(projects[1]["id"])
            queued_future = service._futures[queued["id"]]
            queued_done = threading.Event()
            queued_future.add_done_callback(lambda _: queued_done.set())
            closer = threading.Thread(target=service.close, daemon=True)
            started = time.monotonic()
            try:
                with self.assertLogs("typo_monitor.service", level="ERROR"):
                    closer.start()
                    self.assertTrue(generator.canceled.wait(timeout=2), "Active adapter was not canceled")
                    self.assertTrue(queued_done.wait(timeout=2), "Queued task was not canceled")
                    self.assertTrue(queued_future.cancelled())
                    generator.release.set()
                    closer.join(timeout=3)
                self.assertFalse(closer.is_alive(), "Shutdown did not finish promptly")
                self.assertLess(time.monotonic() - started, 5)
                self.assertEqual(len(generator.calls), 3, "Queued scan ran its generator")
                self.assertEqual(len(resolver.calls), 2, "Canceled scan reached DNS resolution")
                for run in (running, queued):
                    self.assertEqual(service.store.get_run(run["id"])["status"], "failed")
                for project, baseline in zip(projects, baselines):
                    self.assertEqual(service.store.get_domains(project["id"]), before[project["id"]][0])
                    self.assertEqual(service.store.inventory(project["id"]), before[project["id"]][1])
                    self.assertEqual(service.store.get_run(baseline["id"]), baseline)
                with self.assertRaisesRegex(RuntimeError, "shutting down"):
                    service.submit_scan(projects[0]["id"])
                # The data-directory lock must be released for a clean restart.
                with MonitorService(directory, discovery=False,
                                    generator=CooperativeGenerator(), resolver=FixtureResolver()) as restarted:
                    self.assertEqual(restarted.store.get_domains(projects[0]["id"]),
                                     before[projects[0]["id"]][0])
            finally:
                generator.release.set()
                if closer.ident is not None:
                    closer.join(timeout=5)
                service.close()

    def _run_child(self, *, cancel, timeout):
        """Return the helper outcome and prove its isolated child was reaped."""
        spawned = threading.Event()
        processes, outcomes = [], []
        real_popen = subprocess.Popen

        def start_process(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            processes.append(process)
            spawned.set()
            return process

        def run():
            try:
                outcomes.append(_run_command(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    cancel_event=cancel, timeout=timeout,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                ))
            except BaseException as error:
                outcomes.append(error)

        worker = threading.Thread(target=run, daemon=True)
        started = time.monotonic()
        with patch("typo_monitor.adapters.subprocess.Popen", side_effect=start_process):
            try:
                worker.start()
                self.assertTrue(spawned.wait(timeout=2), "Fixture child did not start")
                if timeout > 1:
                    cancel.set()
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive(), "Command helper left a child running")
                self.assertLess(time.monotonic() - started, 5)
                self.assertEqual(len(outcomes), 1)
                self.assertIsNotNone(processes[0].poll(), "Child was not terminated and reaped")
                return outcomes[0]
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=3)
                worker.join(timeout=3)

    def test_shutdown_terminates_and_reaps_an_external_command(self):
        outcome = self._run_child(cancel=threading.Event(), timeout=10)
        self.assertIsInstance(outcome, RuntimeError)
        self.assertIn("shutdown", str(outcome))

    def test_command_deadline_terminates_and_reaps_child_without_shutdown(self):
        outcome = self._run_child(cancel=threading.Event(), timeout=0.1)
        self.assertIsInstance(outcome, subprocess.TimeoutExpired)

    def test_dns_cancellation_prevents_remaining_record_queries(self):
        cancel = threading.Event()
        calls = []

        class CancelDuringQuery:
            def resolve(self, domain, record_type, **kwargs):
                calls.append(record_type)
                cancel.set()
                raise dns.resolver.NoAnswer()

        resolver = DnsResolver(resolver_factory=CancelDuringQuery)
        resolver.cancel_event = cancel
        with self.assertRaisesRegex(RuntimeError, "canceled"):
            resolver.observe("example.com")
        self.assertEqual(calls, ["A"])


if __name__ == "__main__":
    unittest.main()
