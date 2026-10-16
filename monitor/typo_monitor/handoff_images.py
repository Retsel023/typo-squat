"""Bounded image copies for optional handoff; original evidence stays untouched."""

import base64
from io import BytesIO
from pathlib import Path
from uuid import UUID

from PIL import Image

MAX_EDGE = 1280
MAX_IMAGE_BYTES = 256 * 1024
MAX_SOURCE_BYTES = 12 * 1024 * 1024
MAX_SOURCE_PIXELS = 20_000_000


def capture_path(data_dir, capture):
    run_id = str(UUID(capture["run_id"]))
    data_root = Path(data_dir).resolve()
    run = data_root / "runs" / run_id
    relative = capture.get("relative_path")
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("No safe image path was recorded.")
    parts = Path(relative)
    if parts.is_absolute() or ".." in parts.parts or (data_root / "runs").is_symlink() or run.is_symlink():
        raise ValueError("Unsafe capture path.")
    path = run
    for part in parts.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("Capture symlinks are not served.")
    path = path.resolve(strict=True)
    if (not path.is_relative_to(run.resolve()) or not path.is_relative_to(data_root)
            or not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES):
        raise ValueError("Capture is unavailable or exceeds the image transfer limit.")
    return path


def image_payload(data_dir, capture):
    path = capture_path(data_dir, capture)
    source_bytes = path.stat().st_size
    with Image.open(path) as source:
        if source.format not in {"PNG", "JPEG"}:
            raise ValueError("Only PNG/JPEG captures can be transferred.")
        if source.width * source.height > MAX_SOURCE_PIXELS:
            raise ValueError("Capture exceeds the pixel limit.")
        original_format = source.format
        original_size = source.size
        source.load()
        image = source.convert("RGB")
    image.thumbnail((MAX_EDGE, MAX_EDGE), Image.Resampling.LANCZOS)
    quality = 75
    while True:
        output = BytesIO()
        image.save(output, format="JPEG", quality=quality, optimize=True)
        encoded = output.getvalue()
        if len(encoded) <= MAX_IMAGE_BYTES:
            break
        image.thumbnail((max(1, int(image.width * .8)), max(1, int(image.height * .8))), Image.Resampling.LANCZOS)
        quality = max(50, quality - 5)
    mime, mode = "image/jpeg", "resized_copy"
    # Small screenshots can be both sharper and smaller in their original format.
    if image.size == original_size and source_bytes <= min(MAX_IMAGE_BYTES, len(encoded)):
        encoded = path.read_bytes()
        mime = "image/png" if original_format == "PNG" else "image/jpeg"
        mode = "small_original"
    return {"image_data_url": f"data:{mime};base64," + base64.b64encode(encoded).decode("ascii"),
            "image_transfer": {"mode": mode, "width": image.width, "height": image.height,
                               "bytes": len(encoded), "original_bytes": source_bytes}}
