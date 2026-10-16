from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from typo_monitor.legacy import import_inventory
from typo_monitor.service import MonitorService


class LegacyImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "old-output"
        self.output.mkdir()
        self.generator = Mock(spec=["generate"])
        self.generator.generate.side_effect = lambda seeds, workdir: (sorted(set(seeds) | {"fresh.example"}), {"status": "ok"})
        self.resolver = Mock(spec=["resolve"])
        self.resolver.resolve.side_effect = lambda candidates: {
            domain: {"status": "resolved", "records": [["A", "192.0.2.1"]]}
            for domain in candidates
        }
        self.discoverer = Mock(spec=["discover", "executable"])
        self.discoverer.executable = "fixture"
        self.discoverer.discover.return_value = ([], {"status": "ok"})
        self.service = MonitorService(self.root / "monitor", generator=self.generator,
                                      resolver=self.resolver, discoverer=self.discoverer)
        self.addCleanup(self.service.close)

    def write_legacy(self, relative, text):
        path = self.output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def populate_backups(self):
        self.write_legacy("backup-older/combined_domains.txt", "EXAMPLE.com.\nold.example.com\n")
        self.write_legacy("backup-older/deduplicated_domains.txt",
                          "old-typo.example\n*.example.com\n-example.com\nexample.com;id\n")
        self.write_legacy("backup-newer/discovered_subdomains.txt", "new.example.com\n")
        self.write_legacy("checked_domains.txt", "new-typo.example\nhttps://example.com\n127.0.0.1\n")

    def test_import_unions_backups_filters_invalid_names_and_establishes_no_baseline(self):
        self.populate_backups()
        project = import_inventory(self.service, "Migrated", ["example.com"], self.output)
        inventory = self.service.store.inventory(project["id"])
        self.assertEqual(inventory["seeds"], ["example.com", "new.example.com", "old.example.com"])
        self.assertEqual(inventory["candidates"], ["example.com", "new-typo.example", "new.example.com", "old-typo.example", "old.example.com"])
        runs = self.service.store.list_runs(project["id"])
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["status"], "partial")
        self.assertFalse(runs[0]["is_baseline"])
        self.assertEqual(runs[0]["events"], [])
        self.assertEqual(runs[0]["counts"]["checked"], 0)
        source = runs[0]["source_status"]["legacy_import"]
        self.assertEqual(source["files"], 4)
        self.assertEqual(source["invalid_names_excluded"], 5)
        self.assertIsNone(self.service.store.get_project(project["id"])["comparison_scope"])
        self.assertTrue(all(row["first_seen"] is None and row["status"] == "unknown"
                            for row in self.service.store.get_domains(project["id"])))
        self.generator.generate.assert_not_called()
        self.discoverer.discover.assert_not_called()
        self.resolver.resolve.assert_not_called()

    def test_first_fresh_scan_checks_imported_inventory_as_baseline_without_fake_new_events(self):
        self.populate_backups()
        project = import_inventory(self.service, "Migrated", ["example.com"], self.output)
        imported = self.service.store.inventory(project["id"])
        run = self.service.scan_now(project["id"])
        self.assertTrue(run["is_baseline"])
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["events"], [])
        self.assertEqual(run["counts"]["newly_observed"], 0)
        self.assertEqual(self.resolver.resolve.call_args.args[0], sorted(set(imported["candidates"]) | {"fresh.example"}))
        self.assertEqual(self.generator.generate.call_args.args[0], imported["seeds"])
        self.assertEqual(self.service.store.inventory(project["id"])["seeds"], imported["seeds"])
        self.assertEqual(len(self.service.store.list_runs(project["id"])), 2)


if __name__ == "__main__":
    unittest.main()
