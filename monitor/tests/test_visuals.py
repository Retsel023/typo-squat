from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from PIL import Image, ImageDraw

from typo_monitor.visuals import annotate_captures


class VisualTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data_dir = Path(self.temp.name)
        self.workdir = self.data_dir / "runs" / "current-run"
        self.workdir.mkdir(parents=True)
        self.before_dir = self.data_dir / "runs" / "previous-run"
        self.before_dir.mkdir(parents=True)

    @staticmethod
    def page():
        image = Image.new("RGB", (320, 180), "white")
        draw = ImageDraw.Draw(image)
        draw.rectangle((12, 12, 210, 42), fill=(25, 70, 140))
        draw.rectangle((20, 70, 280, 90), fill=(90, 90, 90))
        draw.rectangle((20, 110, 230, 130), fill=(160, 160, 160))
        return image

    def save(self, image, relative, *, before=False, **kwargs):
        target = (self.before_dir if before else self.workdir) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        image.save(target, **kwargs)
        return target

    @staticmethod
    def row(scheme="https", path="https.png", **kwargs):
        return {"scheme": scheme, "relative_path": path, "status": "captured", **kwargs}

    def annotate(self, rows, previous=None):
        captures = {"typo.example": rows}
        result = annotate_captures(captures, workdir=self.workdir, data_dir=self.data_dir,
                                   previous=previous or (lambda domain, scheme: None))
        self.assertIs(result, captures)
        self.assertEqual(len(result["typo.example"]), len(rows))
        return rows

    def previous(self, path="previous.png", **kwargs):
        return {"run_id": "previous-run", "status": "captured", "relative_path": path, **kwargs}

    def test_first_capture_has_pixel_and_file_fingerprints(self):
        self.save(self.page(), "https.png")
        row = self.annotate([self.row()])[0]
        self.assertEqual(row["visual"]["change"], "first_capture")
        self.assertEqual(len(row["visual"]["sha256"]), 64)
        self.assertEqual(len(row["visual"]["pixel_sha256"]), 64)
        self.assertEqual(len(row["visual"]["dhash"]), 16)
        self.assertEqual((row["visual"]["width"], row["visual"]["height"]), (320, 180))

    def test_identical_files_are_unchanged(self):
        image = self.page()
        self.save(image, "https.png")
        self.save(image, "previous.png", before=True)
        row = self.annotate([self.row()], lambda domain, scheme: self.previous())[0]
        self.assertEqual(row["visual"]["change"], "unchanged")
        self.assertEqual(row["visual"]["distance"], 0)
        self.assertEqual(row["visual"]["previous_run_id"], "previous-run")

    def test_reencoded_png_keeps_pixel_identity_despite_different_file_hash(self):
        image = self.page()
        current = self.save(image, "https.png", compress_level=0)
        old = self.save(image, "previous.png", before=True, compress_level=9)
        self.assertNotEqual(current.read_bytes(), old.read_bytes())
        row = self.annotate([self.row()], lambda domain, scheme: self.previous())[0]
        self.assertEqual(row["visual"]["change"], "unchanged")
        self.assertEqual(row["visual"]["distance"], 0)

    def test_http_https_identical_pixels_mark_http_duplicate_without_removing_image(self):
        image = self.page()
        self.save(image, "https.png", compress_level=0)
        self.save(image, "http.png", compress_level=9)
        rows = self.annotate([self.row("http", "http.png"), self.row()])
        self.assertEqual(rows[0]["visual"]["duplicate_of"], "https")
        self.assertEqual(rows[0]["visual"]["duplicate_kind"], "exact")
        self.assertIsNone(rows[1]["visual"]["duplicate_of"])
        self.assertNotEqual(rows[0]["visual"]["sha256"], rows[1]["visual"]["sha256"])
        self.assertEqual(rows[0]["visual"]["pixel_sha256"], rows[1]["visual"]["pixel_sha256"])
        self.assertTrue((self.workdir / "http.png").is_file())

    def test_small_visual_difference_is_similar_but_still_a_changed_image(self):
        image = self.page()
        changed = image.copy()
        ImageDraw.Draw(changed).rectangle((250, 145, 254, 149), fill=(245, 245, 245))
        self.save(image, "https.png")
        self.save(changed, "http.png")
        self.save(image, "previous.png", before=True)
        rows = self.annotate([self.row("http", "http.png"), self.row()], lambda domain, scheme: self.previous())
        self.assertEqual(rows[0]["visual"]["change"], "changed")
        self.assertLessEqual(rows[0]["visual"]["distance"], 3)
        self.assertEqual(rows[0]["visual"]["duplicate_kind"], "similar")
        self.assertNotEqual(rows[0]["visual"]["pixel_sha256"], rows[1]["visual"]["pixel_sha256"])

    def test_uniform_red_and_blue_images_are_not_duplicates(self):
        self.save(Image.new("RGB", (320, 180), "red"), "http.png")
        self.save(Image.new("RGB", (320, 180), "blue"), "https.png")
        rows = self.annotate([self.row("http", "http.png"), self.row()])
        self.assertEqual(rows[0]["visual"]["dhash"], rows[1]["visual"]["dhash"])
        self.assertIsNone(rows[0]["visual"]["duplicate_kind"])

    def test_missing_or_failed_previous_image_is_uncertain_not_first_capture(self):
        self.save(self.page(), "https.png")
        for old in (self.previous("missing.png"), self.previous(status="failed", relative_path=None)):
            with self.subTest(old=old):
                row = self.annotate([self.row()], lambda domain, scheme: old)[0]
                self.assertEqual(row["visual"]["change"], "uncertain")
                self.assertEqual(row["visual"]["previous_run_id"], "previous-run")
                self.assertIn("error", row["visual"])

    def test_capture_failure_never_reads_image_or_previous_capture(self):
        previous = Mock(side_effect=AssertionError("Failed capture cannot be compared"))
        with patch("typo_monitor.visuals._fingerprint") as read:
            row = self.annotate([self.row(status="failed", relative_path=None)], previous)[0]
        read.assert_not_called()
        previous.assert_not_called()
        self.assertEqual(row["visual"]["change"], "uncertain")
        self.assertIsNone(row["visual"]["sha256"])

    def test_current_path_escape_rejected_before_image_read(self):
        for path in ("../previous-run/previous.png", "/tmp/outside.png", "C:/outside.png", "images\\outside.png", "page.svg"):
            with self.subTest(path=path), patch("typo_monitor.visuals._fingerprint") as read:
                row = self.annotate([self.row(path=path)])[0]
                self.assertEqual(row["visual"]["change"], "uncertain")
                read.assert_not_called()

    def test_previous_path_or_run_escape_is_uncertain(self):
        self.save(self.page(), "https.png")
        for old in (self.previous("../outside.png"), self.previous(run_id="../previous-run")):
            with self.subTest(old=old):
                row = self.annotate([self.row()], lambda domain, scheme: old)[0]
                self.assertEqual(row["visual"]["change"], "uncertain")

    def test_symlink_image_is_rejected(self):
        target = self.save(self.page(), "previous.png", before=True)
        try:
            (self.workdir / "https.png").symlink_to(target)
        except OSError:
            self.skipTest("Symlinks unavailable on this platform")
        with patch("typo_monitor.visuals._fingerprint") as read:
            row = self.annotate([self.row()])[0]
        read.assert_not_called()
        self.assertEqual(row["visual"]["change"], "uncertain")


if __name__ == "__main__":
    unittest.main()
