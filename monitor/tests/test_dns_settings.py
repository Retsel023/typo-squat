"""DNS settings are frozen at enqueue time without leaking across clients."""

import os
import tempfile
import threading
import unittest
from unittest.mock import patch

from typo_monitor.__main__ import parser
from typo_monitor.service import MonitorService


class Generator:
    def __init__(self):
        self.block = False
        self.entered = threading.Event()
        self.release = threading.Event()

    def generate(self, seeds, workdir):
        if self.block:
            self.entered.set()
            if not self.release.wait(3):
                raise RuntimeError("Fixture was not released")
        return seeds, {"status": "ok"}


class Resolver:
    workers = 24

    def __init__(self):
        self.calls = []

    def resolve(self, candidates):
        self.calls.append((self.workers, tuple(candidates)))
        return {domain: {"status": "resolved", "records": [["A", "192.0.2.10"]]}
                for domain in candidates}


class DnsSettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.generator, self.resolver = Generator(), Resolver()
        self.service = MonitorService(self.temp.name, discovery=False, capture=False,
                                      scheduling=False, resolver=self.resolver,
                                      generator=self.generator)

    def tearDown(self):
        self.generator.release.set()
        self.service.close()
        self.temp.cleanup()

    def test_queue_freezes_each_clients_workers_and_inheritance_uses_server_default(self):
        first = self.service.create_project("First", ["example.com"], dns_workers=20)
        second = self.service.create_project("Second", ["example.net"], dns_workers=40)
        inherited = self.service.create_project("Inherited", ["example.org"])
        self.generator.block = True
        active = self.service.submit_scan(first["id"])
        self.assertTrue(self.generator.entered.wait(2))
        active_future = self.service._futures[active["id"]]
        queued = self.service.submit_scan(second["id"])
        queued_future = self.service._futures[queued["id"]]
        default = self.service.submit_scan(inherited["id"])
        default_future = self.service._futures[default["id"]]
        self.assertEqual([active["dns_workers"], queued["dns_workers"], default["dns_workers"]], [20, 40, 24])
        self.service.store.set_dns_workers(first["id"], 17)
        self.service.store.set_dns_workers(second["id"], 80)
        self.assertEqual(self.resolver.workers, 20, "Editing settings changed an active adapter")
        self.generator.release.set()
        for future in (active_future, queued_future, default_future):
            self.assertEqual(future.result(3)["status"], "completed")
        self.assertEqual(self.resolver.calls, [(20, ("example.com",)), (40, ("example.net",)), (24, ("example.org",))])
        for run, workers in ((active, 20), (queued, 40), (default, 24)):
            accepted = self.service.store.get_run(run["id"])
            self.assertEqual(accepted["dns_workers"], workers)
            self.assertEqual(accepted["source_status"]["dns"]["workers"], workers)
        # A later run uses the edited value, rechecks its full saved inventory,
        # and changing concurrency never rejects the existing DNS baseline.
        for project, workers in ((second, 80), (first, 17), (inherited, 24)):
            result = self.service.scan_now(project["id"])
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["dns_workers"], workers)
        self.assertEqual(self.resolver.calls[-3:], [(80, ("example.net",)), (17, ("example.com",)), (24, ("example.org",))])

    def test_explicit_settings_survive_restart_while_inherited_uses_new_server_default(self):
        explicit = self.service.create_project("Explicit", ["example.com"], dns_workers=20)
        inherited = self.service.create_project("Inherited", ["example.net"])
        self.service.close()
        self.resolver.workers = 52
        self.service = MonitorService(self.temp.name, discovery=False, capture=False,
                                      scheduling=False, resolver=self.resolver,
                                      generator=self.generator)
        for project, workers in ((explicit, 20), (inherited, 52)):
            self.assertEqual(self.service.dns_status(self.service.store.get_project(project["id"]))["workers"], workers)
            self.assertEqual(self.service.scan_now(project["id"])["dns_workers"], workers)

    def test_scheduled_run_uses_clients_worker_setting(self):
        project = self.service.create_project("Scheduled", ["example.com"], dns_workers=20)
        self.service.store.set_schedule(project["id"], 1)
        with self.service.store._connection(write=True) as db:
            db.execute("UPDATE projects SET schedule_next_run_at=? WHERE id=?",
                       ("2000-01-01T00:00:00+00:00", project["id"]))
        run = self.service.submit_scan(project["id"], _scheduled=True)
        future = self.service._futures.get(run["id"])
        if future:
            future.result(3)
        self.assertEqual(self.service.store.get_run(run["id"])["dns_workers"], 20)
        self.assertEqual(self.resolver.calls, [(20, ("example.com",))])

    def test_invalid_create_setting_does_not_leave_an_orphan_project(self):
        for invalid in (0, 129, True, 20.5, "20"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.service.create_project("Invalid", ["example.com"], dns_workers=invalid)
        self.assertEqual(self.service.store.list_projects(), [])

    def test_cli_default_can_come_from_environment_and_explicit_argument_wins(self):
        with patch.dict(os.environ, {"TYPO_DNS_WORKERS": "20"}):
            self.assertEqual(parser().parse_args(["serve"]).workers, 20)
            self.assertEqual(parser().parse_args(["--workers", "37", "serve"]).workers, 37)
