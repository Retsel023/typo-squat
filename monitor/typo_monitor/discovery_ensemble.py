"""Concurrent discovery engines with one scoped, attributed hostname union."""

from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import re
import threading

from .adapters import _report_progress
from .domains import normalize_domain


_STATUSES = frozenset({"ok", "partial", "unavailable", "failed", "cancelled", "skipped"})


class CombinedDiscovery:
    """Run independent discovery adapters before returning one deduplicated list.

    ``adapters`` may be an ordered mapping of engine keys to adapter instances,
    or a sequence whose keys are derived from each adapter's ``name``. Children
    keep their own output directories and share the caller's cancellation signal.
    """

    name = "Combined discovery"

    def __init__(self, adapters):
        entries = (adapters.items() if isinstance(adapters, Mapping)
                   else ((getattr(adapter, "name", type(adapter).__name__), adapter)
                         for adapter in adapters))
        engines = {}
        identities = set()
        for raw_name, adapter in entries:
            if not isinstance(raw_name, str):
                raise ValueError("Discovery engine names must be text.")
            key = re.sub(r"[^a-z0-9_-]+", "-", raw_name.lower()).strip("-_")
            if not key or len(key) > 64 or key in engines:
                raise ValueError("Discovery engines need distinct, nonempty names.")
            if not callable(getattr(adapter, "discover", None)) or id(adapter) in identities:
                raise ValueError("Each discovery engine must have its own adapter instance.")
            engines[key] = adapter
            identities.add(id(adapter))
        if not engines:
            raise ValueError("At least one discovery engine is required.")
        self._engines = engines
        self.provenance = {}

    @property
    def engines(self):
        """Return engine keys and instances for capability/status reporting."""
        return dict(self._engines)

    def _cancelled(self):
        event = getattr(self, "cancel_event", None)
        return event is not None and event.is_set()

    def discover(self, roots, workdir):
        roots = sorted({normalize_domain(root) for root in roots})
        workdir = Path(workdir).resolve()
        discovery_dir = workdir / "discovery"
        discovery_dir.mkdir(mode=0o700)
        directories = {}
        for key in self._engines:
            directories[key] = discovery_dir / key
            directories[key].mkdir(mode=0o700)

        callback = getattr(self, "progress_callback", None)
        lock = threading.RLock()
        total = len(self._engines)
        finished = set()
        provenance = {}
        statuses = {key: {"status": "queued", "engine": getattr(adapter, "name", key),
                          "discovered": 0, "detail": "Waiting to start."}
                    for key, adapter in self._engines.items()}

        def report(message=None, *, level="info"):
            # Every callback holds this lock so late per-root child messages
            # cannot regress the ensemble's completed-engine counter.
            with lock:
                metrics = {"discovered": len(provenance)}
                for key, state in statuses.items():
                    metrics[f"{key}_status"] = state["status"]
                    metrics[f"{key}_discovered"] = state["discovered"]
                _report_progress(callback, "discovery", message, current=len(finished),
                                 total=total, metrics=metrics, level=level)

        def child_callback(key):
            def progress(_stage, message=None, *, current=None, total=None,
                         metrics=None, level="info"):
                with lock:
                    if key in finished:
                        return
                    count = metrics.get("discovered") if isinstance(metrics, dict) else None
                    if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
                        statuses[key]["discovered"] = count
                    # Child stages and root counters are intentionally ignored;
                    # the ensemble always counts finished engines on this stage.
                    report(f"{statuses[key]['engine']}: {message}" if message else None,
                           level=level)
            return progress

        def run_engine(key, adapter):
            with lock:
                if self._cancelled():
                    return [], {"status": "cancelled", "detail": "Stopped before launch."}
                statuses[key]["status"] = "running"
                report(f"Starting {statuses[key]['engine']} discovery.")
            adapter.cancel_event = getattr(self, "cancel_event", None)
            adapter.run_id = getattr(self, "run_id", None)
            adapter.workdir = directories[key]
            adapter.progress_callback = child_callback(key)
            adapter.proxy_url = getattr(self, "proxy_url", None)
            adapter.proxy_environment = getattr(self, "proxy_environment", None)
            try:
                return adapter.discover(roots, directories[key])
            except Exception as exc:
                return [], {"status": "cancelled" if self._cancelled() else "failed",
                            "detail": f"{type(exc).__name__}: {exc}"[:2000]}

        def accept(key, result):
            try:
                names, raw_status = result
                if isinstance(names, (str, bytes, Mapping)):
                    raise ValueError("Discovery output must be a hostname sequence.")
                found = set()
                for value in names:
                    try:
                        domain = normalize_domain(value)
                    except ValueError:
                        continue
                    if any(domain == root or domain.endswith("." + root) for root in roots):
                        found.add(domain)
                if not isinstance(raw_status, Mapping):
                    raise ValueError("Discovery status must be a mapping.")
                state = raw_status.get("status")
                if state not in _STATUSES:
                    state = "failed"
                status = {"status": state, "engine": statuses[key]["engine"],
                          "discovered": len(found), "detail": str(raw_status.get("detail", ""))[:4000]}
                if isinstance(raw_status.get("version"), str):
                    status["version"] = raw_status["version"][:100]
                if isinstance(raw_status.get("cli_contract"), str):
                    status["cli_contract"] = raw_status["cli_contract"][:100]
                if isinstance(raw_status.get("all_sources"), bool):
                    status["all_sources"] = raw_status["all_sources"]
            except Exception as exc:
                found = set()
                status = {"status": "failed", "engine": statuses[key]["engine"],
                          "discovered": 0, "detail": f"Invalid discovery result: {type(exc).__name__}: {exc}"[:2000]}
            if self._cancelled():
                status["status"] = "cancelled"
                status["detail"] = "Scan cancelled; discovery output was not accepted into the inventory."
            with lock:
                for domain in found:
                    provenance.setdefault(domain, set()).add(key)
                statuses[key] = status
                finished.add(key)
                report(f"{status['engine']}: {status['status']}; {len(found):,} in-scope names.",
                       level="info" if status["status"] == "ok" else "warning")

        report(f"Discovering subdomains with {total} engines concurrently.")
        # The context manager waits for all children, including after cancellation.
        # Their shared signal makes _run_command terminate each owned process
        # group; none can outlive discovery and leak into the next scan.
        with ThreadPoolExecutor(max_workers=min(3, total), thread_name_prefix="discovery") as pool:
            futures = {pool.submit(run_engine, key, adapter): key
                       for key, adapter in self._engines.items()}
            for future in as_completed(futures):
                key = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = ([], {"status": "failed", "detail": f"{type(exc).__name__}: {exc}"[:2000]})
                accept(key, result)

        self.provenance = {domain: sorted(sources) for domain, sources in sorted(provenance.items())}
        cancelled = self._cancelled() or any(state["status"] == "cancelled" for state in statuses.values())
        usable = bool(provenance) or any(state["status"] == "ok" for state in statuses.values())
        state = ("cancelled" if cancelled else "unavailable" if not usable else
                 "ok" if all(item["status"] in {"ok", "skipped"} for item in statuses.values()) else "partial")
        detail = ("Discovery cancelled; previously accepted inventory was preserved." if cancelled else
                  "All discovery engines failed or were unavailable; retained seeds and candidates are still checked." if not usable else
                  f"Combined {total} engines into {len(provenance):,} unique in-scope names. "
                  "Missed discoveries never remove saved domains.")
        status = {"status": state, "engine": self.name, "engines": statuses,
                  "discovered": len(provenance), "detail": detail}
        (workdir / "discovery.json").write_text(
            json.dumps({**status, "roots": roots, "provenance": self.provenance}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        report(detail, level="info" if state == "ok" else "warning")
        if cancelled:
            raise RuntimeError("Scan cancelled or worker shutdown requested; accepted observations were preserved.")
        return sorted(provenance), status
