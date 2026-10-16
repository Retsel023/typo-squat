"""Gowitness JSONL/asset contract tests; all browser execution is simulated."""

import base64
from datetime import datetime
import json
from pathlib import Path
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from typo_monitor.screenshots import GowitnessCapture


PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jrS8AAAAASUVORK5CYII="
)


def metadata(url, filename="asset.png", **kwargs):
    return {"url": url, "file_name": filename, "probed_at": "2026-10-16T10:20:30Z",
            "response_code": 200, "title": "Fixture page", "failed": False,
            "failed_reason": "", "is_pdf": False, **kwargs}


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workdir = self.root / "run"
        self.workdir.mkdir()
        self.chrome = self.root / "chrome"
        self.chrome.write_text("fixture executable", encoding="utf-8")
        self.chrome.chmod(0o755)
        self.capture = GowitnessCapture("fixture-gowitness", str(self.chrome))
        self.commands = []

    def runner(self, scan, *, version="3.2.2"):
        def run(args, **kwargs):
            self.commands.append((args, kwargs))
            self.assertIs(kwargs["shell"], False)
            if args[1] == "version":
                kwargs["stdout"].write(f"fixture banner\ngowitness: {version}\ngit hash: fixture\n")
                return SimpleNamespace(returncode=0)
            return scan(args, kwargs)
        return run

    @staticmethod
    def write_results(args, records, files=None, extra_lines=()):
        screenshot_dir = Path(args[args.index("--screenshot-path") + 1])
        for name, content in (files or {}).items():
            (screenshot_dir / name).write_bytes(content)
        output = Path(args[args.index("--write-jsonl-file") + 1])
        output.write_text("\n".join([json.dumps(record) for record in records] + list(extra_lines)) + "\n", encoding="utf-8")

    def test_both_explicit_scheme_ports_are_mapped_using_jsonl_not_filenames(self):
        def scan(args, kwargs):
            target_file = Path(args[args.index("-f") + 1])
            self.assertEqual(target_file.read_text().splitlines(), ["http://example.com:80", "https://example.com:443"])
            self.assertEqual(args[args.index("--chrome-path") + 1], str(self.chrome))
            self.assertEqual(args[args.index("--screenshot-format") + 1], "png")
            self.write_results(args, [
                metadata("https://example.com:443", "random-b.png", title="Secure", final_url="https://redirect.example/"),
                metadata("http://example.com:80", "random-a.png", title="Plain", response_code=301),
            ], {"random-a.png": PNG, "random-b.png": PNG})
            return SimpleNamespace(returncode=0)
        with patch("typo_monitor.screenshots._run_command", self.runner(scan)):
            result, stage = self.capture.capture(["Example.COM."], self.workdir)
        self.assertEqual(stage["status"], "ok")
        self.assertEqual(stage["captured"], 2)
        http, https = result["example.com"]
        self.assertEqual((http["relative_path"], http["title"], http["http_status"]), ("screenshots/random-a.png", "Plain", 301))
        self.assertEqual((https["relative_path"], https["title"]), ("screenshots/random-b.png", "Secure"))
        self.assertEqual(https["url"], "https://example.com:443")
        self.assertIsNone(http["error"])
        self.assertEqual(datetime.fromisoformat(http["captured_at"]).utcoffset().total_seconds(), 0)

    def test_unavailable_tool_produces_explicit_rows_without_execution(self):
        self.capture.executable = None
        with patch("typo_monitor.screenshots._run_command") as run:
            result, stage = self.capture.capture(["example.com"], self.workdir)
            run.assert_not_called()
        self.assertEqual(stage["status"], "failed")
        self.assertTrue(all(row["status"] == "unavailable" for row in result["example.com"]))

    def test_missing_browser_does_not_trigger_tool_or_browser_download(self):
        self.capture.chrome_path = str(self.root / "missing-browser")
        with patch("typo_monitor.screenshots._run_command") as run:
            result, stage = self.capture.capture(["example.com"], self.workdir)
            run.assert_not_called()
        self.assertEqual(stage["status"], "failed")
        self.assertTrue(all(row["status"] == "unavailable" for row in result["example.com"]))

    def test_unsupported_version_is_explicit_and_never_starts_capture(self):
        with patch("typo_monitor.screenshots._run_command", self.runner(None, version="3.1.1")):
            result, stage = self.capture.capture(["example.com"], self.workdir)
        self.assertEqual(len(self.commands), 1)
        self.assertEqual(stage["status"], "failed")
        self.assertIn("requires 3.2.2", result["example.com"][0]["error"])

    def test_malformed_unrequested_and_missing_metadata_never_make_fake_images(self):
        def scan(args, kwargs):
            self.write_results(args, [metadata("http://example.com:80", failed=True, failed_reason="net::ERR_CONNECTION_REFUSED"),
                                      metadata("https://unrequested.example:443")], extra_lines=("{broken", "[]"))
            return SimpleNamespace(returncode=0)
        with patch("typo_monitor.screenshots._run_command", self.runner(scan)):
            result, stage = self.capture.capture(["example.com"], self.workdir)
        self.assertEqual(set(result), {"example.com"})
        self.assertEqual(stage["status"], "partial")
        self.assertEqual(stage["captured"], 0)
        self.assertIn("CONNECTION_REFUSED", result["example.com"][0]["error"])
        self.assertIn("No JSONL result", result["example.com"][1]["error"])
        self.assertTrue(all(row["relative_path"] is None for row in result["example.com"]))

    def test_nonzero_tool_exit_retains_verified_partial_results(self):
        def scan(args, kwargs):
            self.write_results(args, [metadata("http://example.com:80")], {"asset.png": PNG})
            return SimpleNamespace(returncode=2)
        with patch("typo_monitor.screenshots._run_command", self.runner(scan)):
            result, stage = self.capture.capture(["example.com"], self.workdir)
        self.assertEqual([row["status"] for row in result["example.com"]], ["captured", "failed"])
        self.assertEqual(stage["status"], "partial")
        self.assertIn("code 2", stage["detail"])

    def test_capture_deadline_retains_only_completed_verified_results(self):
        def scan(args, kwargs):
            self.write_results(args, [metadata("http://example.com:80")], {"asset.png": PNG})
            raise subprocess.TimeoutExpired(args, 900)
        with patch("typo_monitor.screenshots._run_command", self.runner(scan)):
            result, stage = self.capture.capture(["example.com"], self.workdir)
        self.assertEqual([row["status"] for row in result["example.com"]], ["captured", "failed"])
        self.assertIn("deadline", stage["detail"])

    def test_escaping_paths_symlinks_wrong_formats_and_extensions_are_rejected(self):
        outside = self.root / "outside.png"
        outside.write_bytes(PNG)
        names = ["../outside.png", str(outside), "subfolder/file.png", "link.png", "html.png", "wrong.jpeg"]
        domains = [f"item{i}.example" for i in range(len(names))]

        def scan(args, kwargs):
            folder = Path(args[args.index("--screenshot-path") + 1])
            (folder / "link.png").symlink_to(outside)
            self.write_results(args, [metadata(f"http://{domain}:80", name) for domain, name in zip(domains, names)],
                               {"html.png": b"<html>not an image</html>", "wrong.jpeg": PNG})
            return SimpleNamespace(returncode=0)
        with patch("typo_monitor.screenshots._run_command", self.runner(scan)):
            result, stage = self.capture.capture(domains, self.workdir)
        self.assertEqual(stage["captured"], 0)
        self.assertTrue(all(rows[0]["relative_path"] is None for rows in result.values()))
        self.assertTrue(all("artifact rejected" in rows[0]["error"] for rows in result.values()))

    def test_filename_collision_for_different_requested_urls_is_not_misattributed(self):
        def scan(args, kwargs):
            self.write_results(args, [metadata("http://example.com:80"), metadata("http://example.net:80")], {"asset.png": PNG})
            return SimpleNamespace(returncode=0)
        with patch("typo_monitor.screenshots._run_command", self.runner(scan)):
            result, stage = self.capture.capture(["example.com", "example.net"], self.workdir)
        self.assertEqual(stage["captured"], 0)
        self.assertTrue(all("share one screenshot" in rows[0]["error"] for rows in result.values()))

    def test_duplicate_requested_url_metadata_is_ambiguous(self):
        def scan(args, kwargs):
            self.write_results(args, [metadata("http://example.com:80", "a.png"), metadata("http://example.com:80", "b.png")],
                               {"a.png": PNG, "b.png": PNG})
            return SimpleNamespace(returncode=0)
        with patch("typo_monitor.screenshots._run_command", self.runner(scan)):
            result, stage = self.capture.capture(["example.com"], self.workdir)
        self.assertIn("Duplicate JSONL", result["example.com"][0]["error"])
        self.assertEqual(stage["captured"], 0)

    def test_missing_file_and_bad_schema_do_not_become_successful_capture(self):
        def scan(args, kwargs):
            self.write_results(args, [metadata("http://example.com:80", "missing.png"),
                                      metadata("https://example.com:443", "asset.png", response_code="200")], {"asset.png": PNG})
            return SimpleNamespace(returncode=0)
        with patch("typo_monitor.screenshots._run_command", self.runner(scan)):
            result, stage = self.capture.capture(["example.com"], self.workdir)
        self.assertTrue(all(row["status"] == "failed" for row in result["example.com"]))
        self.assertEqual(stage["captured"], 0)

    def test_existing_assets_are_never_reused_as_current_capture(self):
        (self.workdir / "screenshots").mkdir()
        (self.workdir / "screenshots" / "old.png").write_bytes(PNG)
        with patch("typo_monitor.screenshots._run_command") as run:
            result, stage = self.capture.capture(["example.com"], self.workdir)
            run.assert_not_called()
        self.assertEqual(stage["status"], "failed")
        self.assertTrue(all(row["relative_path"] is None for row in result["example.com"]))

    def test_empty_input_is_skipped_without_launching_browser(self):
        with patch("typo_monitor.screenshots._run_command") as run:
            result, stage = self.capture.capture([], self.workdir)
            run.assert_not_called()
        self.assertEqual(result, {})
        self.assertEqual(stage["status"], "skipped")

    def test_cancellation_propagates_instead_of_becoming_a_capture_failure(self):
        self.capture.cancel_event = threading.Event()
        self.capture.cancel_event.set()
        with patch("typo_monitor.screenshots._run_command") as run:
            with self.assertRaisesRegex(RuntimeError, "canceled"):
                self.capture.capture(["example.com"], self.workdir)
            run.assert_not_called()
        self.capture.cancel_event.clear()

        def scan(args, kwargs):
            self.capture.cancel_event.set()
            raise RuntimeError("canceled during shutdown")
        with patch("typo_monitor.screenshots._run_command", self.runner(scan)):
            with self.assertRaisesRegex(RuntimeError, "canceled"):
                self.capture.capture(["example.com"], self.workdir)


if __name__ == "__main__":
    unittest.main()
