from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from typo_monitor.progress import (MAX_LOG_BYTES, MAX_LOG_ENTRIES, MAX_MESSAGE_LENGTH,
                                   MAX_OUTPUT_BYTES, MAX_OUTPUT_SOURCES, MAX_SOURCE_BYTES,
                                   RunProgress, read_progress, read_tool_output)


class ProgressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data_dir = Path(self.temp.name) / "data"
        self.run_id = str(uuid4())

    def writer(self, run_id=None):
        return RunProgress(self.data_dir, run_id or self.run_id)

    def output(self, name, text, *, modified=None, run_id=None):
        workdir = self.data_dir / "runs" / (run_id or self.run_id)
        workdir.mkdir(parents=True, exist_ok=True)
        path = workdir / name
        path.write_text(text, encoding="utf-8")
        if modified is not None:
            os.utime(path, (modified, modified))
        return path

    def test_queued_telemetry_never_creates_run_artifacts(self):
        progress = self.writer()
        snapshot = progress.callback("queued", "Waiting for an available worker.")
        self.assertTrue(snapshot["available"])
        self.assertEqual(snapshot, read_progress(self.data_dir, self.run_id))
        self.assertEqual(snapshot["stage"], "queued")
        self.assertEqual(snapshot["logs"][0]["message"], snapshot["message"])
        self.assertTrue(snapshot["started_at"])
        self.assertTrue((self.data_dir / "progress" / f"{self.run_id}.log").exists())
        self.assertFalse((self.data_dir / "runs").exists())

    def test_count_updates_throttle_writes_but_return_latest_counters(self):
        progress = self.writer()
        with patch("typo_monitor.progress.time.monotonic", side_effect=[10, 10.1, 10.2, 11.1]):
            progress.update("dns", "Checking saved candidates.", current=0, total=100)
            current = progress.update("dns", current=10, total=100)
            progress.update("dns", "Checking saved candidates.", current=20, total=100)
            self.assertEqual(current["current"], 10)
            self.assertEqual(read_progress(self.data_dir, self.run_id)["current"], 0)
            progress.update("dns", current=30, total=100)
        persisted = read_progress(self.data_dir, self.run_id)
        self.assertEqual(persisted["current"], 30)
        self.assertEqual(len(persisted["logs"]), 1)

    def test_stage_change_resets_counts_and_terminal_retains_final_counts(self):
        progress = self.writer()
        progress.update("dns", "Checking DNS", current=500, total=500, metrics={"resolved": 20})
        next_stage = progress.update("screenshots", "Capturing pages")
        self.assertIsNone(next_stage["current"])
        self.assertIsNone(next_stage["total"])
        self.assertEqual(next_stage["metrics"], {})
        progress.update("screenshots", current=20, total=20, metrics={"captured": 18})
        finished = progress.update("completed", "Scan finished")
        self.assertEqual((finished["current"], finished["total"]), (20, 20))
        self.assertEqual(finished["metrics"], {"captured": 18})
        self.assertEqual(read_progress(self.data_dir, self.run_id), finished)

    def test_terminal_callbacks_are_immutable_across_writer_instances_and_restart(self):
        for stage in ("completed", "partial", "cancelled", "failed"):
            with self.subTest(stage=stage):
                run_id = str(uuid4())
                writer = self.writer(run_id)
                other = self.writer(run_id)
                writer.update("dns", "Checking DNS", current=1, total=5)
                terminal = other.update(stage, "Stopped")
                self.assertEqual(writer.update("screenshots", "Late callback", current=9), terminal)
                del writer, other
                restarted = self.writer(run_id)
                self.assertEqual(restarted.update("queued", "Restart callback"), terminal)
                self.assertEqual(read_progress(self.data_dir, run_id), terminal)

    def test_log_storage_and_messages_are_bounded_and_returned_values_are_copies(self):
        progress = self.writer()
        for number in range(MAX_LOG_ENTRIES + 25):
            progress.update("dns", f"{number}:" + "\U0001f600" * (MAX_MESSAGE_LENGTH + 100),
                            metrics={"large": "x" * 100_000})
        snapshot = read_progress(self.data_dir, self.run_id)
        self.assertEqual(len(snapshot["logs"]), MAX_LOG_ENTRIES)
        self.assertTrue(snapshot["logs"][0]["message"].startswith("25:"))
        self.assertLessEqual(len(snapshot["message"]), MAX_MESSAGE_LENGTH)
        self.assertLessEqual((self.data_dir / "progress" / f"{self.run_id}.log").stat().st_size, MAX_LOG_BYTES)
        self.assertLessEqual((self.data_dir / "progress" / f"{self.run_id}.json").stat().st_size, 1024 * 1024)
        snapshot["logs"].clear()
        self.assertEqual(len(progress.update("dns")["logs"]), MAX_LOG_ENTRIES)

    def test_parallel_writers_and_readers_never_observe_partial_json(self):
        progress = self.writer()
        progress.update("dns", "Start")
        second = self.writer()
        done = threading.Event()
        failures = []

        def read():
            while not done.is_set():
                snapshot = read_progress(self.data_dir, self.run_id)
                if not snapshot["available"] or snapshot["stage"] != "dns":
                    failures.append(snapshot)
                    return

        def write(writer, prefix):
            for index in range(40):
                writer.update("dns", f"{prefix} {index}", current=index, total=40)

        with ThreadPoolExecutor(max_workers=3) as pool:
            reader = pool.submit(read)
            first = pool.submit(write, progress, "first")
            second_future = pool.submit(write, second, "second")
            first.result(timeout=10)
            second_future.result(timeout=10)
            done.set()
            reader.result(timeout=10)
        self.assertEqual(failures, [])
        self.assertEqual(len(read_progress(self.data_dir, self.run_id)["logs"]), 81)
        self.assertEqual(list((self.data_dir / "progress").glob("*.tmp")), [])

    def test_absent_invalid_and_malformed_legacy_snapshots_are_unavailable(self):
        self.assertFalse(read_progress(None, self.run_id)["available"])
        self.assertEqual(read_tool_output(None, self.run_id), [])
        for invalid in ("../outside", "bad-id", "", None):
            with self.subTest(invalid=invalid):
                self.assertFalse(read_progress(self.data_dir, invalid)["available"])
                self.assertEqual(read_tool_output(self.data_dir, invalid), [])
                with self.assertRaises((ValueError, TypeError)):
                    self.writer(invalid if invalid is not None else "invalid")
        progress_dir = self.data_dir / "progress"
        progress_dir.mkdir(parents=True, exist_ok=True)
        path = progress_dir / f"{self.run_id}.json"
        for malformed in (b"{unfinished", b"\xff", b"[]", b'{"available":true}', b"x" * (1024 * 1024 + 1)):
            path.write_bytes(malformed)
            self.assertFalse(read_progress(self.data_dir, self.run_id)["available"])
        self.assertFalse(read_progress(self.data_dir, str(uuid4()))["available"])

    def test_cross_run_snapshots_and_output_are_isolated(self):
        other = str(uuid4())
        self.writer().update("dns", "First run")
        self.writer(other).update("queued", "Second run")
        self.output("generator.log", "first output")
        self.output("generator.log", "second output", run_id=other)
        self.assertEqual(read_progress(self.data_dir, self.run_id)["message"], "First run")
        self.assertEqual(read_progress(self.data_dir, other)["message"], "Second run")
        first_text = " ".join(row["text"] for row in read_tool_output(self.data_dir, self.run_id))
        self.assertIn("first output", first_text)
        self.assertNotIn("second output", first_text)
        self.assertNotIn("Second run", first_text)

    def test_old_runs_show_only_allowlisted_command_output_without_progress(self):
        self.output("generator.log", "generated successfully\n")
        self.output("gowitness.log", "capture complete\n")
        self.output("subfinder-12.stderr.log", "diagnostic\n")
        self.output("subfinder-12.txt", "www.example.org\n")
        for forbidden in ("input-candidates.txt", "generated-12.txt", "subfinder-latest.txt", "private.log"):
            self.output(forbidden, "DO NOT DISPLAY")
        rows = read_tool_output(self.data_dir, self.run_id)
        self.assertFalse(read_progress(self.data_dir, self.run_id)["available"])
        self.assertEqual({row["name"] for row in rows},
                         {"generator.log", "gowitness.log", "subfinder-12.stderr.log", "subfinder-12.txt"})
        self.assertNotIn("DO NOT DISPLAY", " ".join(row["text"] for row in rows))

    def test_output_tail_limits_sources_and_prioritizes_recent_nonempty_logs(self):
        for number in range(15):
            self.output(f"subfinder-{number}.txt", f"output {number}\n" + "x" * (MAX_SOURCE_BYTES * 2), modified=100 + number)
        self.output("gowitness.log", "", modified=1000)
        self.output("generator.log", " \x1b[31m\x00\n", modified=1001)
        rows = read_tool_output(self.data_dir, self.run_id)
        self.assertLessEqual(len(rows), MAX_OUTPUT_SOURCES)
        self.assertEqual(rows[0]["name"], "subfinder-14.txt")
        self.assertLessEqual(sum(len(row["text"].encode("utf-8")) for row in rows), MAX_OUTPUT_BYTES)
        self.assertTrue(all(len(row["text"].encode("utf-8")) <= MAX_SOURCE_BYTES for row in rows))
        self.assertTrue(all(row["truncated"] for row in rows))
        self.assertNotIn("subfinder-0.txt", {row["name"] for row in rows})
        self.assertNotIn("gowitness.log", {row["name"] for row in rows})

    def test_output_removes_terminal_controls_but_preserves_html_for_ui_escaping(self):
        self.output("generator.log", "\x1b[31mred\x1b[0m\x00\x07\n<script>unsafe</script>\tend")
        text = read_tool_output(self.data_dir, self.run_id)[0]["text"]
        self.assertEqual(text, "red\n<script>unsafe</script>\tend")

    @unittest.skipUnless(hasattr(os, "symlink"), "Symlinks are unavailable")
    def test_symlink_files_and_directories_are_never_read_or_overwritten(self):
        outside = Path(self.temp.name) / "private"
        outside.mkdir()
        secret = outside / "secret.log"
        secret.write_text("private contents")
        self.data_dir.mkdir()
        (self.data_dir / "progress").symlink_to(outside, target_is_directory=True)
        (outside / f"{self.run_id}.json").write_text("{}")
        self.assertFalse(read_progress(self.data_dir, self.run_id)["available"])
        with self.assertRaises(ValueError):
            self.writer()
        (self.data_dir / "progress").unlink()
        writer = self.writer()
        writer.path.symlink_to(secret)
        self.assertFalse(read_progress(self.data_dir, self.run_id)["available"])
        with self.assertRaises(ValueError):
            writer.update("queued", "Never overwrite a symlink")
        self.assertEqual(secret.read_text(), "private contents")
        writer.path.unlink()
        self.output("subfinder-1.txt", "public")
        (self.data_dir / "runs" / self.run_id / "generator.log").symlink_to(secret)
        rows = read_tool_output(self.data_dir, self.run_id)
        self.assertEqual([row["name"] for row in rows], ["subfinder-1.txt"])
        run_dir = self.data_dir / "runs" / self.run_id
        (run_dir / "subfinder-1.txt").unlink()
        (run_dir / "generator.log").unlink()
        run_dir.rmdir()
        run_dir.symlink_to(outside, target_is_directory=True)
        self.assertEqual(read_tool_output(self.data_dir, self.run_id), [])


if __name__ == "__main__":
    unittest.main()
