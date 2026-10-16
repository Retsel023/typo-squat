"""Local screenshot comparison; similarities are hints, never website verdicts.

Exact comparison uses decoded RGB pixels, so changing PNG compression does not
look like a page change. Perceptual hashes only identify potentially redundant
HTTP/HTTPS images. A different pixel digest always remains a changed image.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Callable

from PIL import Image, ImageChops, ImageOps, ImageStat


NEAR_DHASH_THRESHOLD = 3
NEAR_RGB_RMS_THRESHOLD = 8.0


@dataclass(frozen=True)
class _Fingerprint:
    sha256: str
    pixel_sha256: str
    dhash: str
    width: int
    height: int
    thumbnail: Image.Image


def _safe_image_path(base: Path, relative_path: str) -> Path:
    """Confine an existing raster file and reject symlinks on every component."""
    if (not isinstance(relative_path, str) or not relative_path
            or "\\" in relative_path or any(ord(c) < 32 for c in relative_path)
            or PurePosixPath(relative_path).is_absolute()
            or PureWindowsPath(relative_path).drive
            or ".." in PurePosixPath(relative_path).parts
            or PurePosixPath(relative_path).suffix.lower() not in {".png", ".jpg", ".jpeg"}):
        raise ValueError("Image path must be a confined relative PNG or JPEG file.")
    base = Path(base).absolute()
    if any(parent.is_symlink() for parent in (base, *base.parents)):
        raise ValueError("Image directories cannot contain symlinks.")
    root = base.resolve(strict=True)
    path = base
    for part in PurePosixPath(relative_path).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("Image paths cannot contain symlinks.")
    path = path.resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError("Image is outside its capture directory.")
    return path


def _previous_path(data_dir: Path, capture: dict) -> Path:
    run_id = capture.get("run_id")
    if (not isinstance(run_id, str) or not run_id or run_id in {".", ".."}
            or "/" in run_id or "\\" in run_id or PureWindowsPath(run_id).drive):
        raise ValueError("Previous image has no valid run directory.")
    relative_path = capture.get("relative_path")
    # Validate independently before adding the trusted run-directory prefix.
    if (not isinstance(relative_path, str) or PurePosixPath(relative_path).is_absolute()
            or PureWindowsPath(relative_path).drive or "\\" in relative_path
            or ".." in PurePosixPath(relative_path).parts):
        raise ValueError("Previous image has an unsafe relative path.")
    return _safe_image_path(data_dir, f"runs/{run_id}/{relative_path}")


def _fingerprint(path: Path) -> _Fingerprint:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    with Image.open(path) as image:
        if image.format not in {"PNG", "JPEG"} or getattr(image, "n_frames", 1) != 1:
            raise ValueError("Capture is not a single-frame PNG or JPEG image.")
        image.load()
        oriented = ImageOps.exif_transpose(image)
        rgba = oriented.convert("RGBA")
        # Compare what is visible on the review panel's white background.
        rgb = Image.alpha_composite(Image.new("RGBA", rgba.size, "white"), rgba).convert("RGB")
    width, height = rgb.size
    pixels = hashlib.sha256(f"RGB:{width}x{height}\0".encode("ascii"))
    pixels.update(rgb.tobytes())
    gray = rgb.convert("L").resize((9, 8), Image.Resampling.LANCZOS)
    samples = gray.tobytes()
    difference_hash = 0
    for row in range(8):
        for column in range(8):
            index = row * 9 + column
            difference_hash = (difference_hash << 1) | (samples[index] > samples[index + 1])
    return _Fingerprint(digest.hexdigest(), pixels.hexdigest(), f"{difference_hash:016x}", width, height,
                        rgb.resize((32, 32), Image.Resampling.BILINEAR))


def _distance(first: _Fingerprint, second: _Fingerprint) -> int:
    return (int(first.dhash, 16) ^ int(second.dhash, 16)).bit_count()


def _near_duplicate(first: _Fingerprint, second: _Fingerprint) -> bool:
    if _distance(first, second) > NEAR_DHASH_THRESHOLD:
        return False
    if (abs(first.width - second.width) > max(2, max(first.width, second.width) * 0.02)
            or abs(first.height - second.height) > max(2, max(first.height, second.height) * 0.02)):
        return False
    first_aspect, second_aspect = first.width / first.height, second.width / second.height
    if abs(first_aspect - second_aspect) > max(first_aspect, second_aspect) * 0.01:
        return False
    # Uniform red and blue images both have all-zero dHashes. The RGB guard
    # prevents that and other large color differences from becoming duplicates.
    difference = ImageStat.Stat(ImageChops.difference(first.thumbnail, second.thumbnail))
    rms = math.sqrt(sum(value * value for value in difference.rms) / 3)
    return rms <= NEAR_RGB_RMS_THRESHOLD


def _empty_visual() -> dict:
    return {"sha256": None, "pixel_sha256": None, "dhash": None, "width": None, "height": None,
            "change": "uncertain", "distance": None, "previous_run_id": None,
            "duplicate_of": None, "duplicate_kind": None}


def annotate_captures(captures: dict, *, workdir: Path,
                      previous: Callable[[str, str], dict | None], data_dir: Path) -> dict:
    """Add visual metadata in place, retaining every capture and its raw image.

    ``previous(domain, scheme)`` supplies the last successful capture metadata.
    A known previous image that is missing/unreadable yields uncertainty. Image
    changes describe pixels, not page ownership, intent, or security findings.
    """
    cache = {}

    def fingerprint(path):
        if path not in cache:
            cache[path] = _fingerprint(path)
        return cache[path]

    for domain, attempts in captures.items():
        current = {}
        for attempt in attempts:
            visual = _empty_visual()
            attempt["visual"] = visual
            scheme = attempt.get("scheme")
            if attempt.get("status") != "captured" or scheme not in {"http", "https"}:
                visual["error"] = "No successful image is available for comparison."
                continue
            try:
                image = fingerprint(_safe_image_path(workdir, attempt.get("relative_path")))
            except (OSError, ValueError, Image.DecompressionBombError) as exc:
                visual["error"] = f"Current image could not be compared: {exc}"
                continue
            current[scheme] = (attempt, image)
            visual.update(sha256=image.sha256, pixel_sha256=image.pixel_sha256, dhash=image.dhash,
                          width=image.width, height=image.height)
            try:
                old = previous(domain, scheme)
                if old is None:
                    visual["change"] = "first_capture"
                    continue
                visual["previous_run_id"] = old.get("run_id")
                if old.get("status") != "captured":
                    raise ValueError("Previous attempt did not produce an image.")
                before = fingerprint(_previous_path(data_dir, old))
                visual["distance"] = _distance(image, before)
                visual["change"] = "unchanged" if image.pixel_sha256 == before.pixel_sha256 else "changed"
            except (OSError, ValueError, TypeError, AttributeError, Image.DecompressionBombError) as exc:
                visual["error"] = f"Previous image could not be compared: {exc}"
        if "http" in current and "https" in current:
            # Prefer HTTPS as the gallery representative; keep HTTP in history.
            http_attempt, http_image = current["http"]
            _, https_image = current["https"]
            if http_image.pixel_sha256 == https_image.pixel_sha256:
                http_attempt["visual"].update(duplicate_of="https", duplicate_kind="exact")
            elif _near_duplicate(http_image, https_image):
                http_attempt["visual"].update(duplicate_of="https", duplicate_kind="similar")
    return captures
