import base64
import hashlib
from io import BytesIO
import json
from pathlib import Path
import random
import socket
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image

from typo_monitor.handoff_images import MAX_EDGE, MAX_IMAGE_BYTES, MAX_SOURCE_PIXELS, image_payload
from typo_monitor.preview import build_preview, write_preview
from typo_monitor.store import Store


class PreviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data_dir = Path(self.temp.name)
        self.store = Store(self.data_dir)
        self.project = self.store.create_project("Example", ["example.com"])

    def complete(self, domains, *, references=False, images=True):
        run = self.store.start_run(self.project["id"])
        captures = {}
        for domain in list(domains) + (["example.com"] if references else []):
            relative = f"screenshots/https-{domain}.png"
            if images:
                path = self.data_dir / "runs" / run["id"] / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                with Image.new("RGB", (80, 60), "white" if domain == "example.com" else "blue") as image:
                    image.save(path)
            captures[domain] = [{"scheme": "https", "url": f"https://{domain}", "status": "captured",
                "relative_path": relative, "captured_at": "2026-10-16T12:00:00Z", "visual": {"change": "first_capture"}}]
        return self.store.finish_run(run["id"], seeds=["example.com"], candidates=list(captures),
            observations={domain: {"status": "resolved", "records": [["A", "192.0.2.1"]]} for domain in captures},
            source_status={"dns": {"status": "ok"}}, screenshots=captures,
            provenance={domain: ["example.com"] for domain in domains} if references else None)

    def test_image_copy_is_bounded_and_full_original_is_unchanged(self):
        run = self.complete(["large.example"], images=False)
        capture = self.store.get_capture(run["id"], "large.example", "https")
        path = self.data_dir / "runs" / run["id"] / capture["relative_path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        size = (2400, 1600)
        pixels = random.Random(17).randbytes(size[0] * size[1] * 3)
        with Image.frombytes("RGB", size, pixels) as image:
            image.save(path, compress_level=0)
        del pixels
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        payload = image_payload(self.data_dir, capture)
        encoded = base64.b64decode(payload["image_data_url"].split(",", 1)[1], validate=True)
        self.assertLessEqual(len(encoded), 256 * 1024)
        self.assertEqual(MAX_IMAGE_BYTES, 256 * 1024)
        self.assertEqual(MAX_EDGE, 1280)
        self.assertEqual(payload["image_transfer"]["bytes"], len(encoded))
        self.assertLess(len(encoded), path.stat().st_size)
        with Image.open(BytesIO(encoded)) as copy:
            self.assertLessEqual(max(copy.size), 1280)
            self.assertEqual(copy.size, (payload["image_transfer"]["width"], payload["image_transfer"]["height"]))
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
        with Image.open(path) as original:
            self.assertEqual(original.size, size)

    def test_small_original_is_kept_when_it_is_smaller_than_jpeg_copy(self):
        run = self.complete(["small.example"])
        capture = self.store.get_capture(run["id"], "small.example", "https")
        path = self.data_dir / "runs" / run["id"] / capture["relative_path"]
        payload = image_payload(self.data_dir, capture)
        self.assertEqual(payload["image_transfer"]["mode"], "small_original")
        self.assertEqual(base64.b64decode(payload["image_data_url"].split(",", 1)[1]), path.read_bytes())

    def test_source_pixel_limit_rejects_compressed_huge_image_before_decoding(self):
        run = self.complete(["large.example"], images=False)
        capture = self.store.get_capture(run["id"], "large.example", "https")
        path = self.data_dir / "runs" / run["id"] / capture["relative_path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        self.assertEqual(MAX_SOURCE_PIXELS, 20_000_000)
        with Image.new("RGB", (5000, 4001), "white") as image:
            image.save(path)
        with patch("PIL.Image.Image.load", side_effect=AssertionError("Oversize source must not decode")):
            with self.assertRaisesRegex(ValueError, "pixel limit"):
                image_payload(self.data_dir, capture)

    def test_preview_counts_repeated_reference_transfers_but_only_encodes_once(self):
        run = self.complete(["alpha.example", "beta.example"], references=True)
        captures = {row["domain"]: row for row in self.store.list_run_captures(run["id"])}
        payloads = {domain: image_payload(self.data_dir, capture) for domain, capture in captures.items()}
        original_digests = {domain: hashlib.sha256((self.data_dir / "runs" / run["id"] / capture["relative_path"]).read_bytes()).hexdigest()
                            for domain, capture in captures.items()}
        with (patch("typo_monitor.preview.image_payload", wraps=image_payload) as encode,
              patch.object(socket.socket, "connect", side_effect=AssertionError("Preview cannot contact a service")),
              patch("socket.create_connection", side_effect=AssertionError("Preview cannot contact a service"))):
            report = build_preview(self.store, self.data_dir, run["id"])
        self.assertEqual(encode.call_count, 3)
        self.assertEqual(report["batch"]["pairs"], 2)
        self.assertEqual(report["batch"]["images"], 4)
        self.assertEqual(report["external_requests"], 0)
        expected_inline = sum(len(payloads[domain]["image_data_url"]) for domain in ("alpha.example", "beta.example", "example.com", "example.com"))
        expected_bytes = sum(payloads[domain]["image_transfer"]["bytes"] for domain in ("alpha.example", "beta.example", "example.com", "example.com"))
        self.assertEqual(report["batch"]["inline_image_bytes"], expected_inline)
        self.assertEqual(report["batch"]["compact_image_bytes"], expected_bytes)
        self.assertTrue(all(len([image for image in item["images"] if image["role"] == "reference"]) == 1 for item in report["items"]))
        for domain, capture in captures.items():
            path = self.data_dir / "runs" / run["id"] / capture["relative_path"]
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), original_digests[domain])

    def test_saved_reports_contain_counts_not_image_bytes_or_external_resources(self):
        run = self.complete(["alpha.example"], references=True)
        with patch.object(socket.socket, "connect", side_effect=AssertionError("Local report cannot send data")):
            report = build_preview(self.store, self.data_dir, run["id"])
            json_path, html_path = write_preview(report, self.data_dir / "reports" / "local.json")
        self.assertEqual(json.loads(json_path.read_text(encoding="utf-8")), report)
        for path in (json_path, html_path):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("data:image/", text)
            self.assertNotIn("image_data_url", text)
            self.assertNotIn("<img", text)
        self.assertIn("default-src 'none'", html_path.read_text(encoding="utf-8"))

    def test_preview_batches_are_bounded_and_page_counts_stay_accurate(self):
        run = self.complete(["alpha.example", "beta.example", "gamma.example"])
        first = build_preview(self.store, self.data_dir, run["id"], limit=2)
        self.assertEqual(first["summary"]["selected_pairs"], 3)
        self.assertEqual(first["batch"]["pairs"], 2)
        self.assertEqual(first["next_offset"], 2)
        last = build_preview(self.store, self.data_dir, run["id"], limit=2, offset=2)
        self.assertEqual(last["batch"]["pairs"], 1)
        self.assertIsNone(last["next_offset"])
        for options in ({"limit": 0}, {"limit": 26}, {"offset": -1}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                build_preview(self.store, self.data_dir, run["id"], **options)

    def test_missing_image_is_counted_as_unavailable_without_leaking_its_path(self):
        run = self.complete(["missing.example"], images=False)
        report = build_preview(self.store, self.data_dir, run["id"])
        self.assertEqual(report["batch"]["unavailable_images"], 1)
        self.assertEqual(report["batch"]["ready_pairs"], 0)
        self.assertEqual(report["batch"]["inline_image_bytes"], 0)
        self.assertNotIn(str(self.data_dir), json.dumps(report))


if __name__ == "__main__":
    unittest.main()
