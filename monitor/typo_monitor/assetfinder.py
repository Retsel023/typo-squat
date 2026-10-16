"""Passive Assetfinder discovery with bounded, retained command output."""

from pathlib import Path
import math
import shutil
import subprocess

from .adapters import _report_progress, _run_command
from .domains import normalize_domain


# Assetfinder has no version flag. This identifies the supported CLI and the
# Docker build pin, not a runtime verification of an arbitrary native binary.
ASSETFINDER_VERSION = "0.1.1"
ASSETFINDER_COMMIT = "4e95d8701aae8cff1c27af2626eb22ba110ad583"
_MAX_LINE = 64 * 1024


class Assetfinder:
    name = "Assetfinder"
    version = ASSETFINDER_VERSION

    def __init__(self, executable=None, timeout=600):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Discovery timeout must be a positive number of seconds.")
        located = shutil.which(str(executable or "assetfinder"))
        self.executable = str(Path(located).resolve()) if located else None
        self.timeout = timeout

    def _check_cancel(self):
        event = getattr(self, "cancel_event", None)
        if event is not None and event.is_set():
            raise RuntimeError("Scan cancelled or worker shutdown requested; accepted observations were preserved.")

    @staticmethod
    def _names(output, root):
        """Read complete lines only, including output from failed/expired jobs."""
        found = set()
        if not output.exists():
            return found
        with output.open(encoding="utf-8", errors="replace") as stream:
            while raw := stream.readline(_MAX_LINE + 1):
                if len(raw) > _MAX_LINE or not raw.endswith("\n"):
                    # Discard an oversized or interrupted line without loading
                    # an unbounded string or accepting a truncated hostname.
                    while raw and not raw.endswith("\n"):
                        raw = stream.readline(_MAX_LINE + 1)
                    continue
                try:
                    domain = normalize_domain(raw.strip())
                except ValueError:
                    continue
                # Upstream's --subs-only checks a string suffix without a label
                # boundary, so its output still needs strict client scoping.
                if domain == root or domain.endswith("." + root):
                    found.add(domain)
        return found

    def discover(self, roots, workdir):
        roots = sorted({normalize_domain(root) for root in roots})
        workdir = Path(workdir).resolve()
        callback = getattr(self, "progress_callback", None)
        self._check_cancel()
        if not self.executable:
            detail = "Assetfinder is not installed; retained seeds and candidates are still checked."
            _report_progress(callback, "discovery", detail, current=0,
                             total=len(roots), level="warning")
            return [], {"status": "unavailable", "engine": self.name,
                        "cli_contract": ASSETFINDER_VERSION,
                        "detail": detail, "discovered": 0}

        found, errors = set(), []
        for index, root in enumerate(roots):
            self._check_cancel()
            output = workdir / f"assetfinder-{index}.txt"
            log = workdir / f"assetfinder-{index}.stderr.log"
            _report_progress(callback, "discovery",
                f"Assetfinder: discovering subdomains for {root}.",
                current=index, total=len(roots), metrics={"discovered": len(found)})
            try:
                with output.open("x", encoding="utf-8") as stdout, log.open("x", encoding="utf-8") as stderr:
                    result = _run_command(
                        [self.executable, "--subs-only", root],
                        stdout=stdout, stderr=stderr, timeout=self.timeout,
                        cancel_event=getattr(self, "cancel_event", None),
                        shell=False, text=True, cwd=workdir,
                    )
                if result.returncode:
                    errors.append(f"{root}: exit {result.returncode}; see {log.name}")
            except subprocess.TimeoutExpired:
                errors.append(f"{root}: timed out after {self.timeout:g}s; partial output retained in {output.name}")
            except OSError as exc:
                errors.append(f"{root}: {type(exc).__name__}; see {log.name}")
            self._check_cancel()
            try:
                found.update(self._names(output, root))
            except OSError as exc:
                errors.append(f"{root}: could not read {output.name} ({type(exc).__name__})")
            _report_progress(callback, "discovery",
                f"Assetfinder finished {index + 1}/{len(roots)} roots; {len(found):,} in-scope names found.",
                current=index + 1, total=len(roots), metrics={"discovered": len(found)},
                level="warning" if errors else "info")

        # Upstream catches individual provider errors without writing stderr or
        # returning a nonzero status. Describe this limitation even on exit 0.
        limitation = "Assetfinder does not report individual upstream provider failures; absence is not evidence of removal."
        return sorted(found), {
            "status": "partial" if errors else "ok",
            "engine": self.name,
            "cli_contract": ASSETFINDER_VERSION,
            "discovered": len(found),
            "detail": "; ".join([*errors, limitation]) if errors else f"Passive discovery process completed. {limitation}",
        }
