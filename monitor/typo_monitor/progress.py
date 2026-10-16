"""Bounded live telemetry, separate from accepted scan observations.

Progress is disposable: an absent or unreadable legacy file never prevents the
UI from displaying a run. Tool output is a bounded tail of explicit log names.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
from uuid import UUID, uuid4
import weakref


MAX_LOG_ENTRIES = 200
MAX_MESSAGE_LENGTH = 1000
MAX_PROGRESS_BYTES = 1024 * 1024
MAX_LOG_BYTES = 512 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
MAX_SOURCE_BYTES = 12 * 1024
MAX_OUTPUT_SOURCES = 8
TERMINAL_STAGES = frozenset({"completed", "partial", "cancelled", "failed"})
_TOOL_NAME = re.compile(
    r"(?:generator\.log|gowitness\.log|(?:subfinder|assetfinder)-\d+\.(?:stderr\.log|txt)"
    r"|amass-version\.log|amass-\d+\.(?:stdout\.log|stderr\.log|engine\.log|txt)"
    r"|massdns\.(?:stderr\.log|jsonl)|massdns-(?:a|aaaa|cname)\.(?:stderr\.log|jsonl))\Z")
_DISCOVERY_TOOL_NAMES = {
    "amass": re.compile(r"(?:amass-version\.log|amass-\d+\.(?:stdout\.log|stderr\.log|engine\.log|txt))\Z"),
    "subfinder": re.compile(r"subfinder-\d+\.(?:stderr\.log|txt)\Z"),
    "assetfinder": re.compile(r"assetfinder-\d+\.(?:stderr\.log|txt)\Z"),
}
_ANSI = re.compile(r"\x1b(?:\][^\x07\x1b]*(?:\x07|\x1b\\)|\[[0-?]*[ -/]*[@-~]|[@-_])")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_REGISTRY_LOCK = threading.Lock()
_REGISTRY = weakref.WeakValueDictionary()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _unavailable():
    return {"available": False, "stage": None, "message": None, "current": None,
            "total": None, "metrics": {}, "updated_at": None, "started_at": None, "logs": []}


def _run_id(value):
    if not isinstance(value, (str, UUID)):
        raise ValueError("Run ID must be a UUID.")
    return str(UUID(str(value)))


def _clean_text(value, *, single_line=False, limit=None):
    value = _CONTROL.sub("", _ANSI.sub("", str(value)))
    if single_line:
        value = " ".join(value.split())
    return value if limit is None else value[:limit]


def _safe_path(path, *, directory=False):
    """Reject symlinks on every existing component, including data ancestors."""
    path = Path(path).absolute()
    for component in (*reversed(path.parents), path):
        if component.is_symlink():
            raise ValueError("Telemetry paths cannot contain symlinks.")
    if path.exists() and (not path.is_dir() if directory else not path.is_file()):
        raise ValueError("Unexpected telemetry path type.")
    return path


def _open_read(path):
    path = _safe_path(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("Telemetry source must be a regular file.")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def _count(value):
    if value is None or isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    raise ValueError("Progress counts must be nonnegative integers.")


def _metrics(value):
    """Keep telemetry JSON small, even if an adapter supplies an oversized value."""
    if not isinstance(value, dict):
        return {}

    def small(item, depth=0):
        if item is None or isinstance(item, bool):
            return item
        if isinstance(item, (int, float)):
            return item if math.isfinite(item) else None
        if isinstance(item, str):
            return _clean_text(item, limit=MAX_MESSAGE_LENGTH)
        if depth < 2 and isinstance(item, dict):
            return {_clean_text(key, single_line=True, limit=100): small(val, depth + 1)
                    for key, val in list(item.items())[:50]}
        if depth < 2 and isinstance(item, (list, tuple)):
            return [small(val, depth + 1) for val in item[:50]]
        return _clean_text(item, single_line=True, limit=100)

    result = small(value)
    while result and len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > 16 * 1024:
        result.pop(next(reversed(result)))
    return result


def _load(path):
    try:
        with _open_read(path) as source:
            raw = source.read(MAX_PROGRESS_BYTES + 1)
        if len(raw) > MAX_PROGRESS_BYTES:
            return _unavailable()
        value = json.loads(raw)
        if (not isinstance(value, dict) or value.get("available") is not True
                or not isinstance(value.get("stage"), str) or not value["stage"]
                or not isinstance(value.get("started_at"), str)
                or not isinstance(value.get("updated_at"), str)
                or not isinstance(value.get("logs"), list)):
            return _unavailable()
        result = {"available": True, "stage": _clean_text(value["stage"], single_line=True, limit=80),
                  "message": None if value.get("message") is None else _clean_text(value["message"], single_line=True, limit=MAX_MESSAGE_LENGTH),
                  "current": _count(value.get("current")), "total": _count(value.get("total")),
                  "metrics": _metrics(value.get("metrics")), "started_at": value["started_at"][:100],
                  "updated_at": value["updated_at"][:100], "logs": []}
        for entry in value["logs"][-MAX_LOG_ENTRIES:]:
            if (not isinstance(entry, dict)
                    or not all(isinstance(entry.get(key), str) for key in ("time", "level", "message", "stage"))):
                return _unavailable()
            result["logs"].append({"time": entry["time"][:100], "level": _clean_text(entry["level"], single_line=True, limit=20),
                                   "message": _clean_text(entry["message"], single_line=True, limit=MAX_MESSAGE_LENGTH),
                                   "stage": _clean_text(entry["stage"], single_line=True, limit=80)})
        return result
    except (OSError, ValueError, TypeError, RecursionError):
        return _unavailable()


def read_progress(data_dir, run_id):
    """Read an atomic telemetry snapshot; missing/unsafe files are unavailable."""
    if data_dir is None:
        return _unavailable()
    try:
        return _load(Path(data_dir) / "progress" / f"{_run_id(run_id)}.json")
    except (OSError, TypeError, ValueError):
        return _unavailable()


def _atomic_write(path, payload):
    path = _safe_path(path)
    _safe_path(path.parent, directory=True)
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(payload)
            target.flush()
        # Check again before replacement so an unexpected link is never replaced.
        _safe_path(path)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


class _SharedState:
    def __init__(self, path):
        self.lock = threading.RLock()
        self.value = _load(path)
        self.last_write = float("-inf")


class RunProgress:
    """Write bounded run telemetry; count-only updates flush at most once/second."""

    def __init__(self, data_dir, run_id):
        if data_dir is None:
            raise ValueError("A data directory is required for progress updates.")
        self.run_id = _run_id(run_id)
        self.directory = _safe_path(Path(data_dir) / "progress", directory=True)
        self.directory.mkdir(parents=True, exist_ok=True)
        _safe_path(self.directory, directory=True)
        self.path = self.directory / f"{self.run_id}.json"
        self.log_path = self.directory / f"{self.run_id}.log"
        _safe_path(self.path)
        _safe_path(self.log_path)
        with _REGISTRY_LOCK:
            self._shared = _REGISTRY.get(str(self.path))
            if self._shared is None:
                self._shared = _SharedState(self.path)
                _REGISTRY[str(self.path)] = self._shared

    def update(self, stage, message=None, *, current=None, total=None, metrics=None, level="info"):
        stage = _clean_text(stage, single_line=True, limit=80).lower()
        if not stage:
            raise ValueError("A progress stage is required.")
        current, total = _count(current), _count(total)
        message = None if message is None else _clean_text(message, single_line=True, limit=MAX_MESSAGE_LENGTH)
        level = _clean_text(level, single_line=True, limit=20).lower() or "info"
        with self._shared.lock:
            old = self._shared.value
            if old["stage"] in TERMINAL_STAGES:
                return deepcopy(old)
            value = deepcopy(old)
            changed_stage = old["stage"] != stage
            terminal = stage in TERMINAL_STAGES
            stamp = _now()
            if changed_stage and not terminal:
                value.update(message=None, current=None, total=None, metrics={})
            value.update(available=True, stage=stage, updated_at=stamp,
                         started_at=old["started_at"] or stamp)
            if current is not None:
                value["current"] = current
            if total is not None:
                value["total"] = total
            if metrics is not None:
                value["metrics"] = _metrics(metrics)
            meaningful = message is not None and (changed_stage or message != old["message"])
            if message is not None:
                value["message"] = message
            if meaningful:
                value["logs"].append({"time": stamp, "level": level, "message": message, "stage": stage})
                value["logs"] = value["logs"][-MAX_LOG_ENTRIES:]
            self._shared.value = value
            monotonic = time.monotonic()
            if changed_stage or terminal or meaningful or monotonic - self._shared.last_write >= 1:
                payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                if len(payload) > MAX_PROGRESS_BYTES:
                    raise ValueError("Progress telemetry exceeds its storage limit.")
                _atomic_write(self.path, payload)
                if meaningful:
                    lines = [f"{item['time']} [{item['level']}] {item['stage']}: {item['message']}\n"
                             for item in value["logs"]]
                    log = "".join(lines).encode("utf-8")
                    if len(log) > MAX_LOG_BYTES:
                        log = log[-MAX_LOG_BYTES:]
                        log = log[log.find(b"\n") + 1:]
                    _atomic_write(self.log_path, log)
                self._shared.last_write = monotonic
            return deepcopy(value)

    callback = update


def read_tool_output(data_dir, run_id):
    """Return bounded recent actual output; never read raw candidate inventories."""
    if data_dir is None:
        return []
    try:
        run_id = _run_id(run_id)
        root = _safe_path(Path(data_dir), directory=True)
        progress = _safe_path(root / "progress", directory=True)
        workdir = _safe_path(root / "runs" / run_id, directory=True)
    except (OSError, TypeError, ValueError):
        return []
    candidates = []
    if progress.exists():
        candidates.append((f"progress/{run_id}.log", progress / f"{run_id}.log"))
    if workdir.exists():
        try:
            candidates.extend((path.name, path) for path in workdir.iterdir() if _TOOL_NAME.fullmatch(path.name))
        except OSError:
            pass
        # Ensemble adapters have fixed, isolated output folders. Enumerate only
        # these three directories and their explicit tool names; never recurse
        # into Amass state/configuration or follow directory symlinks.
        for engine, names in _DISCOVERY_TOOL_NAMES.items():
            try:
                directory = _safe_path(workdir / "discovery" / engine, directory=True)
                if directory.exists():
                    candidates.extend((f"discovery/{engine}/{path.name}", path)
                                      for path in directory.iterdir() if names.fullmatch(path.name))
            except (OSError, ValueError):
                continue
    sources = []
    for name, path in candidates:
        try:
            _safe_path(path)
            info = path.stat()
            if stat.S_ISREG(info.st_mode) and info.st_size:
                sources.append((info.st_mtime_ns, name, path))
        except (OSError, ValueError):
            continue
    sources.sort(key=lambda item: (item[0], item[1]), reverse=True)
    output, remaining = [], MAX_OUTPUT_BYTES
    for _, name, path in sources:
        if len(output) >= MAX_OUTPUT_SOURCES or remaining <= 0:
            break
        try:
            with _open_read(path) as source:
                size = os.fstat(source.fileno()).st_size
                cap = min(MAX_SOURCE_BYTES, remaining)
                source.seek(max(0, size - cap))
                raw = source.read(cap)
            text = _clean_text(raw.decode("utf-8", errors="replace"))
            # Removing terminal escapes/control codes can leave a nominal source empty.
            if not text.strip():
                continue
            output.append({"name": name, "text": text, "truncated": size > len(raw)})
            remaining -= len(raw)
        except (OSError, ValueError):
            continue
    return output
