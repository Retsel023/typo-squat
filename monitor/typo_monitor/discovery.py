"""Amass discovery with a pinned CLI contract and retained per-run evidence."""

from pathlib import Path
import json
import math
import os
import re
import shutil
import subprocess

from .adapters import _report_progress, _run_command
from .domains import normalize_domain
from .discovery_config import provider_config


AMASS_VERSION = "4.2.0"
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
# v4 enum's -o writes typed asset relationships, not a plain hostname list.
_RELATION = re.compile(r"(.+?) \(([^()]+)\) --> (\S+) --> (.+?) \(([^()]+)\)")


class Amass:
    name = "Amass"
    version = AMASS_VERSION

    def __init__(self, executable=None, timeout=600, config=None):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Discovery timeout must be a positive number of seconds.")
        located = shutil.which(str(executable or "amass"))
        self.executable = str(Path(located).resolve()) if located else None
        self.timeout = timeout
        self.config = Path(config).resolve() if config else None

    def _check_cancel(self):
        event = getattr(self, "cancel_event", None)
        if event is not None and event.is_set():
            raise RuntimeError("Scan cancelled or worker shutdown requested; accepted observations were preserved.")

    def _version(self, workdir):
        log = workdir / "amass-version.log"
        try:
            with log.open("x", encoding="utf-8") as output:
                result = _run_command([self.executable, "-version"],
                    stdout=output, stderr=subprocess.STDOUT,
                    timeout=min(10, self.timeout), cancel_event=getattr(self, "cancel_event", None),
                    shell=False, text=True, env=getattr(self, "proxy_environment", None))
            with log.open(encoding="utf-8", errors="replace") as output:
                text = _ANSI.sub("", output.read(16 * 1024))
            versions = set(re.findall(r"\bv?(\d+\.\d+\.\d+)\b", text))
            if result.returncode != 0 or versions != {AMASS_VERSION}:
                detected = ", ".join(sorted(versions)) or "unrecognized version"
                return f"Amass {AMASS_VERSION} is required; found {detected}. See {log.name}. No fallback engine was used."
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"Could not verify Amass {AMASS_VERSION}: {type(exc).__name__}; see {log.name}. No fallback engine was used."
        return None

    @staticmethod
    def _names(output, root):
        found = set()
        if not output.exists():
            return found
        with output.open(encoding="utf-8", errors="replace") as stream:
            while raw := stream.readline(64 * 1024 + 1):
                if len(raw) > 64 * 1024 or not raw.endswith("\n"):
                    while raw and not raw.endswith("\n"):
                        raw = stream.readline(64 * 1024 + 1)
                    continue
                match = _RELATION.fullmatch(raw.strip())
                if match is None:
                    continue
                left, left_type, _, right, right_type = match.groups()
                for value, kind in ((left, left_type), (right, right_type)):
                    if kind != "FQDN":
                        continue
                    try:
                        domain = normalize_domain(value)
                    except ValueError:
                        continue
                    if domain == root or domain.endswith("." + root):
                        found.add(domain)
        return found

    def discover(self, roots, workdir):
        workdir = Path(workdir).resolve()
        roots = [normalize_domain(root) for root in roots]
        callback = getattr(self, "progress_callback", None)

        def unavailable(detail):
            _report_progress(callback, "discovery", detail, current=0, total=len(roots), level="warning")
            return [], {"status": "unavailable", "engine": self.name, "version": AMASS_VERSION,
                        "detail": detail, "discovered": 0}

        self._check_cancel()
        if getattr(self, "proxy_url", None):
            return [], {"status": "skipped", "engine": self.name, "version": AMASS_VERSION,
                        "discovered": 0, "detail": "Amass 4.2 is skipped while discovery proxying is enabled: "
                        "its internal DNS/resolver traffic cannot be covered by the HTTP provider proxy. "
                        "No direct Amass requests were started. Use combined discovery, Subfinder or Assetfinder for proxied enumeration."}
        if not self.executable:
            return unavailable(f"Amass {AMASS_VERSION} is not installed; retained seeds and candidates are still checked. No fallback engine was used.")
        try:
            configuration = provider_config(self.config)
        except (OSError, ValueError) as exc:
            return unavailable(f"Amass provider configuration is invalid: {exc}. No fallback engine was used.")
        problem = self._version(workdir)
        self._check_cancel()
        if problem:
            return unavailable(problem)
        found, errors = set(), []
        for index, root in enumerate(roots):
            self._check_cancel()
            output = workdir / f"amass-{index}.txt"
            stdout_path = workdir / f"amass-{index}.stdout.log"
            stderr_path = workdir / f"amass-{index}.stderr.log"
            engine_log = workdir / f"amass-{index}.engine.log"
            state = workdir / f"amass-db-{index}"
            state.mkdir(mode=0o700)
            effective_config = state / "config.yaml"
            descriptor = os.open(effective_config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as target:
                # JSON is a YAML subset; only the validated provider path is
                # included, never scope, credentials or remote graph settings.
                json.dump(configuration, target)
            # An isolated graph prevents another client's stored assets leaking
            # into this run. Only the monitor's accepted inventory persists seeds.
            command = [self.executable, "enum", "-nocolor", "-d", root,
                       "-dir", str(state), "-o", str(output), "-log", str(engine_log),
                       "-config", str(effective_config)]
            # Allow Amass to finish gracefully within the outer wall-clock budget.
            # Its CLI timeout is integer minutes; short budgets use only our limit.
            if self.timeout >= 120:
                command.extend(["-timeout", str(max(1, math.floor(self.timeout / 60) - 1))])
            _report_progress(callback, "discovery",
                f"Amass {AMASS_VERSION}: discovering subdomains for {root}.",
                current=index, total=len(roots), metrics={"discovered": len(found)})
            try:
                with stdout_path.open("x", encoding="utf-8") as stdout, stderr_path.open("x", encoding="utf-8") as stderr:
                    result = _run_command(command, stdout=stdout, stderr=stderr,
                        timeout=self.timeout, cancel_event=getattr(self, "cancel_event", None),
                        shell=False, text=True, cwd=workdir, env=getattr(self, "proxy_environment", None))
                if result.returncode:
                    errors.append(f"{root}: exit {result.returncode}; see {stderr_path.name}")
                elif not output.is_file():
                    errors.append(f"{root}: Amass produced no asset output file; see {stderr_path.name}")
            except (OSError, subprocess.TimeoutExpired) as exc:
                errors.append(f"{root}: {type(exc).__name__}; see {stderr_path.name}")
            self._check_cancel()
            # Failed/expired discovery can still contribute valid in-scope names.
            found.update(self._names(output, root))
            _report_progress(callback, "discovery",
                f"Amass finished {index + 1}/{len(roots)} roots; {len(found):,} in-scope names found.",
                current=index + 1, total=len(roots), metrics={"discovered": len(found)},
                level="warning" if errors else "info")
        return sorted(found), {"status": "partial" if errors else "ok", "engine": self.name,
            "version": AMASS_VERSION, "discovered": len(found),
            "detail": "; ".join(errors) if errors else "Amass discovery completed. Saved asset relationships are context; fresh DNS checks determine current status."}
