"""Client scan controls use isolated files, cooperative fixtures and no network."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from typo_monitor.adapters import _run_command
from typo_monitor.service import MonitorService


class ControlledService(MonitorService):
    """Keep periodic ticks deterministic; exercise queue acceptance directly."""

    def _schedule(self):
        self._closed.wait()


class Generator:
    def __init__(self):
        self.signature = "controls-generator:v1"
        self.calls = []
        self.block_seed = None
        self.entered = threading.Event()
        self.observed_cancel = threading.Event()
        self.active_event = None
        self.raise_on_cancel = False

    def cache_signature(self):
        return self.signature

    def generate(self, seeds, workdir):
        self.calls.append(tuple(seeds))
        if self.block_seed in seeds:
            self.active_event = self.cancel_event
            self.entered.set()
            if not self.cancel_event.wait(timeout=5):
                raise RuntimeError("Fixture never received cancellation")
            self.observed_cancel.set()
            if self.raise_on_cancel:
                raise RuntimeError("Fixture adapter interrupted")
        self.provenance = {domain: [seed] for seed in seeds
                           for domain in (seed, "typo-" + seed)}
        return sorted(self.provenance), {"status": "ok"}


class Resolver:
    def __init__(self):
        self.calls = []

    def resolve(self, candidates):
        self.calls.append(tuple(candidates))
        return {domain: {"status": "resolved", "records": [["A", "192.0.2.10"]]}
                for domain in candidates}


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.generator, self.resolver = Generator(), Resolver()
        self.service = self.open_service()
        self.first = self.service.create_project("First", ["example.com"])
        self.second = self.service.create_project("Second", ["example.net"])

    def tearDown(self):
        self.service.close()
        self.temp.cleanup()

    def open_service(self, interval_hours=0):
        return ControlledService(self.temp.name, discovery=False, capture=False,
                                 generator=self.generator, resolver=self.resolver,
                                 interval_hours=interval_hours)

    def make_due(self, project):
        self.service.store.set_schedule(project["id"], 1)
        with self.service.store._connection(write=True) as db:
            db.execute("UPDATE projects SET schedule_next_run_at=? WHERE id=?",
                       ("2000-01-01T00:00:00.000000+00:00", project["id"]))

    def status(self, project):
        return self.service.schedule_status(self.service.store.get_project(project["id"]))

    def test_queued_stop_does_not_cancel_active_client_and_running_stop_preserves_state(self):
        baselines = [self.service.scan_now(project["id"]) for project in (self.first, self.second)]
        before = {project["id"]: (self.service.store.get_domains(project["id"]),
                                  self.service.store.inventory(project["id"]))
                  for project in (self.first, self.second)}
        self.generator.signature = "controls-generator:v2"
        self.generator.block_seed = "example.com"
        running = self.service.submit_scan(self.first["id"])
        self.assertTrue(self.generator.entered.wait(timeout=2), "Running fixture did not start")
        running_future = self.service._futures[running["id"]]
        queued = self.service.submit_scan(self.second["id"])
        queued_future = self.service._futures[queued["id"]]
        stopped_queue = self.service.cancel_scan(queued["id"])
        self.assertEqual(stopped_queue["status"], "cancelled")
        self.assertTrue(queued_future.cancelled())
        self.assertFalse(self.generator.active_event.is_set(), "Stopping a queued client interrupted another client")
        self.assertFalse(self.service._closed.is_set(), "A user stop shut down the server")
        self.assertEqual(self.service.cancel_scan(queued["id"]), stopped_queue)
        stopped_running = self.service.cancel_scan(running["id"])
        self.assertEqual(stopped_running["status"], "cancelled")
        self.assertTrue(self.generator.observed_cancel.wait(timeout=2))
        running_future.result(timeout=3)
        self.assertEqual(self.service.cancel_scan(running["id"]), stopped_running)
        self.assertEqual(len(self.generator.calls), 3, "The cancelled queued scan executed its generator")
        self.assertEqual(len(self.resolver.calls), 2, "Stopped work reached DNS acceptance")
        for project, baseline in zip((self.first, self.second), baselines):
            self.assertEqual(self.service.store.get_domains(project["id"]), before[project["id"]][0])
            self.assertEqual(self.service.store.inventory(project["id"]), before[project["id"]][1])
            self.assertEqual(self.service.store.get_run(baseline["id"]), baseline)
            self.assertEqual(self.service.store.generation_cache(project["id"], "controls-generator:v2"), set())
            self.assertEqual(self.service.store.generation_cache(project["id"], "controls-generator:v1"),
                             set(project["roots"]))
        self.generator.block_seed = None
        next_run = self.service.scan_now(self.second["id"])
        self.assertEqual(next_run["status"], "completed", "Stopping one run poisoned future adapter cancellation")

    def test_adapter_exception_after_stop_does_not_replace_cancelled_with_failed(self):
        self.generator.block_seed, self.generator.raise_on_cancel = "example.com", True
        run = self.service.submit_scan(self.first["id"])
        self.assertTrue(self.generator.entered.wait(timeout=2))
        future = self.service._futures[run["id"]]
        self.service.cancel_scan(run["id"])
        future.result(timeout=3)
        self.assertEqual(self.service.store.get_run(run["id"])["status"], "cancelled")
        self.assertEqual(self.resolver.calls, [])
        self.assertEqual(self.service.store.generation_cache(self.first["id"], self.generator.signature), set())

    def test_stop_after_completion_is_idempotent_and_keeps_completed_result(self):
        completed = self.service.scan_now(self.first["id"])
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(self.service.cancel_scan(completed["id"]), completed)
        self.assertEqual(self.service.cancel_scan(completed["id"]), completed)

    def test_per_client_settings_survive_restart_and_manual_off_overrides_global_default(self):
        self.service.close()
        self.service = self.open_service(interval_hours=12)
        inherited = self.status(self.first)
        self.assertTrue(inherited["inherited"])
        self.assertEqual(inherited["interval_hours"], 12)
        self.service.store.set_schedule(self.first["id"], 6)
        self.service.store.set_schedule(self.second["id"], 0)
        explicit = self.status(self.first)
        disabled = self.status(self.second)
        self.assertEqual(explicit["interval_hours"], 6)
        self.assertFalse(explicit["inherited"])
        self.assertIsNotNone(explicit["next_run_at"])
        self.assertEqual(disabled["interval_hours"], 0)
        self.assertFalse(disabled["inherited"])
        self.assertIsNone(disabled["next_run_at"])
        self.service.close()
        self.service = self.open_service(interval_hours=24)
        self.assertEqual(self.status(self.first), explicit)
        self.assertEqual(self.status(self.second), disabled)
        inherited_client = self.service.create_project("Inherited", ["example.org"])
        self.assertTrue(self.status(inherited_client)["inherited"])
        self.assertEqual(self.status(inherited_client)["interval_hours"], 24)

    def test_scheduler_exists_with_zero_global_default_and_accepts_due_client_once(self):
        self.assertIsNotNone(self.service._scheduler)
        self.assertTrue(self.service._scheduler.is_alive())
        self.make_due(self.first)
        self.assertLess(datetime.fromisoformat(self.status(self.first)["next_run_at"]), datetime.now(timezone.utc))
        run = self.service.submit_scan(self.first["id"], _scheduled=True)
        future = self.service._futures.get(run["id"])
        if future:
            future.result(timeout=3)
        self.assertEqual(self.service.store.get_run(run["id"])["status"], "completed")
        self.assertGreater(datetime.fromisoformat(self.status(self.first)["next_run_at"]), datetime.now(timezone.utc))
        self.assertIsNone(self.service.submit_scan(self.first["id"], _scheduled=True))
        self.assertEqual(len(self.service.store.list_runs(self.first["id"])), 1)

    def test_disabled_or_future_schedule_is_rechecked_before_queue_acceptance(self):
        self.make_due(self.first)
        self.assertIsNotNone(self.status(self.first)["next_run_at"])
        self.service.store.set_schedule(self.first["id"], 0)
        self.assertIsNone(self.service.submit_scan(self.first["id"], _scheduled=True))
        self.service.store.set_schedule(self.first["id"], 1)
        self.assertIsNone(self.service.submit_scan(self.first["id"], _scheduled=True))
        self.assertEqual(self.service.store.list_runs(self.first["id"]), [])
        self.assertEqual(self.generator.calls, [])

    def test_manual_scan_advances_client_due_time(self):
        self.make_due(self.first)
        run = self.service.scan_now(self.first["id"])
        self.assertEqual(run["status"], "completed")
        self.assertGreater(datetime.fromisoformat(self.status(self.first)["next_run_at"]), datetime.now(timezone.utc))
        self.assertIsNone(self.service.submit_scan(self.first["id"], _scheduled=True))

    def test_periodic_tick_queues_due_client_once_and_skips_active_off_and_demo(self):
        self.make_due(self.first)
        self.service.store.set_schedule(self.second["id"], 0)
        demo_client = self.service.create_project("Demo", ["example.org"])
        demo = self.service.store.start_run(demo_client["id"])
        self.service.store.finish_run(demo["id"], seeds=["example.org"], candidates=["example.org"],
                                     observations={"example.org": {"status": "resolved", "records": [["A", "192.0.2.10"]]}},
                                     source_status={"demo": {"status": "ok"}})
        self.make_due(demo_client)
        self.generator.block_seed = "example.com"
        self.service._schedule_tick()
        self.assertTrue(self.generator.entered.wait(timeout=2))
        running = self.service.store.list_runs(self.first["id"])[0]
        future = self.service._futures[running["id"]]
        self.service._schedule_tick()
        self.assertEqual(len(self.service.store.list_runs(self.first["id"])), 1)
        self.assertEqual(self.service.store.list_runs(self.second["id"]), [])
        self.assertEqual(len(self.service.store.list_runs(demo_client["id"])), 1)
        self.assertEqual(self.generator.calls, [("example.com",)])
        self.service.cancel_scan(running["id"])
        future.result(timeout=3)

    def test_stopping_overdue_explicit_schedule_restarts_interval_from_stop_time(self):
        self.service.store.set_schedule(self.first["id"], 1)
        self.generator.block_seed = "example.com"
        run = self.service.submit_scan(self.first["id"])
        self.assertTrue(self.generator.entered.wait(timeout=2))
        future = self.service._futures[run["id"]]
        # Model a scan whose runtime has exceeded its scheduling interval.
        with self.service.store._connection(write=True) as db:
            db.execute("UPDATE runs SET started_at=? WHERE id=?",
                       ("2000-01-01T00:00:00.000000+00:00", run["id"]))
            db.execute("UPDATE projects SET schedule_next_run_at=? WHERE id=?",
                       ("2000-01-01T01:00:00.000000+00:00", self.first["id"]))
        stopped = self.service.cancel_scan(run["id"])
        cancellation_returned_at = datetime.now(timezone.utc)
        future.result(timeout=3)
        schedule = self.status(self.first)
        expected = datetime.fromisoformat(stopped["finished_at"]) + timedelta(hours=1)
        actual = datetime.fromisoformat(schedule["next_run_at"])
        self.assertGreaterEqual(actual, expected)
        self.assertLessEqual(actual, cancellation_returned_at + timedelta(hours=1))
        self.assertFalse(schedule["inherited"])
        self.service._schedule_tick()
        self.assertEqual(len(self.service.store.list_runs(self.first["id"])), 1,
                         "The scheduler immediately restarted a stopped overdue scan")
        self.assertEqual(self.service.cancel_scan(run["id"]), stopped)
        self.assertEqual(self.status(self.first), schedule, "Repeated Stop pushed the due time again")
        self.service.close()
        self.service = self.open_service()
        self.assertEqual(self.status(self.first), schedule)

    def test_stopping_overdue_inherited_schedule_uses_finished_time_across_restart(self):
        self.service.close()
        self.service = self.open_service(interval_hours=2)
        self.generator.block_seed = "example.com"
        run = self.service.submit_scan(self.first["id"])
        self.assertTrue(self.generator.entered.wait(timeout=2))
        future = self.service._futures[run["id"]]
        with self.service.store._connection(write=True) as db:
            db.execute("UPDATE runs SET started_at=? WHERE id=?",
                       ("2000-01-01T00:00:00.000000+00:00", run["id"]))
        stopped = self.service.cancel_scan(run["id"])
        future.result(timeout=3)
        schedule = self.status(self.first)
        expected = datetime.fromisoformat(stopped["finished_at"]) + timedelta(hours=2)
        self.assertTrue(schedule["inherited"])
        self.assertEqual(datetime.fromisoformat(schedule["next_run_at"]), expected)
        project = self.service.store.get_project(self.first["id"])
        self.assertFalse(self.service._schedule_due(project, now=expected - timedelta(microseconds=1)))
        self.assertTrue(self.service._schedule_due(project, now=expected))
        self.service._schedule_tick()
        self.assertEqual(len(self.service.store.list_runs(self.first["id"])), 1)
        self.service.close()
        self.service = self.open_service(interval_hours=2)
        self.assertEqual(self.status(self.first), schedule)

    def test_due_demo_client_is_never_accepted_for_real_scanning(self):
        demo = self.service.store.start_run(self.first["id"])
        self.service.store.finish_run(demo["id"], seeds=["example.com"], candidates=["example.com"],
                                     observations={"example.com": {"status": "resolved", "records": [["A", "192.0.2.10"]]}},
                                     source_status={"demo": {"status": "ok"}})
        self.make_due(self.first)
        self.assertIsNone(self.service.submit_scan(self.first["id"], _scheduled=True))
        self.assertEqual(self.generator.calls, [])


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux process-group cleanup regression")
class ProcessTreeTests(unittest.TestCase):
    def test_cancel_stops_tool_and_its_child_process(self):
        cancel = threading.Event()
        outcomes = []
        grandchild = None
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "child.pid"
            grandchild_script = ("import os,pathlib,signal,sys,time; "
                                 "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                                 "p=pathlib.Path(sys.argv[1]+'.tmp'); p.write_text(str(os.getpid())); "
                                 "p.replace(sys.argv[1]); time.sleep(60)")
            script = ("import subprocess,sys,time; "
                      "subprocess.Popen([sys.executable,'-c'," + repr(grandchild_script)
                      + ",sys.argv[1]]); time.sleep(60)")

            def run():
                try:
                    outcomes.append(_run_command([sys.executable, "-c", script, str(pid_file)],
                                                 cancel_event=cancel, timeout=10,
                                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
                except BaseException as exc:
                    outcomes.append(exc)

            def is_active(pid):
                try:
                    state = Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()[0]
                    return state not in {"Z", "X"}
                except FileNotFoundError:
                    return False

            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            try:
                deadline = time.monotonic() + 2
                while not pid_file.exists() and time.monotonic() < deadline:
                    cancel.wait(timeout=0.01)
                self.assertTrue(pid_file.exists(), "Fixture tool did not spawn its child")
                grandchild = int(pid_file.read_text())
                self.assertTrue(is_active(grandchild))
                cancel.set()
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive(), "Tool cancellation exceeded its bound")
                deadline = time.monotonic() + 1
                while is_active(grandchild) and time.monotonic() < deadline:
                    threading.Event().wait(0.01)
                self.assertFalse(is_active(grandchild), "The tool stopped but left its child process running")
                self.assertEqual(len(outcomes), 1)
                self.assertIsInstance(outcomes[0], RuntimeError)
            finally:
                cancel.set()
                if grandchild is not None and is_active(grandchild):
                    os.kill(grandchild, signal.SIGKILL)
                worker.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
