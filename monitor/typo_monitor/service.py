"""Single-process scan worker with durable inventory and isolated run artifacts."""

from concurrent.futures import CancelledError, ThreadPoolExecutor
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from importlib import metadata
from pathlib import Path
import json
import logging
import math
import shutil
import threading
import time
from uuid import UUID

from .adapters import AilGenerator, DnsResolver, Subfinder
from .assetfinder import Assetfinder
from .discovery import Amass
from .discovery_ensemble import CombinedDiscovery
from .massdns import MassDnsResolver
from .domains import normalize_domain, parse_domains
from .progress import RunProgress
from .store import Store

LOG = logging.getLogger(__name__)


class _CancellationSignal:
    """Read a run's stop request together with whole-worker shutdown."""

    def __init__(self, shutdown, requested):
        self.shutdown, self.requested = shutdown, requested

    def is_set(self):
        return self.shutdown.is_set() or self.requested.is_set()

    def wait(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        while not self.is_set():
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                return False
            self.requested.wait(.05 if remaining is None else min(.05, remaining))
        return True

    # Preserve the injected-adapter shutdown signal interface. User stop
    # requests set only the separate per-run Event through cancel_scan().
    def set(self):
        self.shutdown.set()

    def clear(self):
        self.shutdown.clear()


class InstanceLock:
    """Protect recovery from accidentally failing another live server's runs."""

    def __init__(self, data_dir):
        self.file = (Path(data_dir) / "instance.lock").open("a+b")
        try:
            if __import__("os").name == "nt":
                import msvcrt
                self.file.seek(0)
                self.file.write(b"0")
                self.file.flush()
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.file.close()
            raise RuntimeError("Another monitor process is using this data directory. Use its web UI to start scans.") from exc

    def close(self):
        self.file.close()


class MonitorService:
    def __init__(self, data_dir, *, discovery=True, resolver=None, generator=None,
                 discoverer=None, interval_hours=0, max_candidates=250_000, parking_classifier=None,
                 capture=True, capturer=None, scheduling=True):
        if not math.isfinite(interval_hours) or interval_hours < 0 or max_candidates < 1:
            raise ValueError("Schedule must be nonnegative and candidate limit positive.")
        default_workers = getattr(resolver, "workers", 24)
        if (not isinstance(default_workers, int) or isinstance(default_workers, bool)
                or not 1 <= default_workers <= 128):
            raise ValueError("DNS workers must be an integer between 1 and 128.")
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._instance = InstanceLock(self.data_dir)
        try:
            self.store = Store(self.data_dir)
            self.store.recover_interrupted_runs()
            self._cleanup_deleted_artifacts()
        except Exception:
            self._instance.close()
            raise
        self.discovery = discovery
        self.resolver = resolver or MassDnsResolver()
        # Adapters are reused by the single scan worker. Keep the server default
        # separate from whichever client's value was applied to the last run.
        self.dns_workers = default_workers
        self.generator = generator or AilGenerator()
        self.discoverer = discoverer or CombinedDiscovery({
            "amass": Amass(), "subfinder": Subfinder(all_sources=True), "assetfinder": Assetfinder()})
        if parking_classifier is None and isinstance(self.resolver, DnsResolver):
            from .parking import ParkingClassifier
            parking_classifier = ParkingClassifier(nameservers=self.resolver.nameservers)
        self.parking_classifier = parking_classifier
        if capture and capturer is None and isinstance(self.resolver, DnsResolver):
            from .screenshots import GowitnessCapture
            capturer = GowitnessCapture()
        self.capturer = capturer if capture else None
        self.capture_enabled = capture
        self.interval_hours = interval_hours
        self.max_candidates = max_candidates
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="scan")
        self._mutex = threading.Lock()
        self._futures = {}
        self._cancel_events = {}
        self._progress = {}
        self._proxy_snapshots = {}
        self._execution = threading.local()
        self._closed = threading.Event()
        for adapter in (self.resolver, self.generator, self.discoverer):
            adapter.cancel_event = self._closed
        if self.parking_classifier:
            self.parking_classifier.cancel_event = self._closed
        if self.capturer:
            self.capturer.cancel_event = self._closed
        self._scheduler = None
        if scheduling:
            self._scheduler = threading.Thread(target=self._schedule, daemon=True, name="schedule")
            self._scheduler.start()

    def create_project(self, name, roots, *, dns_workers=None):
        name = name.strip()
        if not name or len(name) > 120 or any(ord(c) < 32 for c in name):
            raise ValueError("Project name must contain 1–120 printable characters.")
        roots = parse_domains("\n".join(roots))
        if not roots or len(roots) > 500:
            raise ValueError("Enter between 1 and 500 root domains.")
        if dns_workers is not None and (not isinstance(dns_workers, int)
                or isinstance(dns_workers, bool) or not 1 <= dns_workers <= 128):
            raise ValueError("DNS workers must be an integer between 1 and 128.")
        project = self.store.create_project(name, roots)
        return self.store.set_dns_workers(project["id"], dns_workers) if dns_workers is not None else project

    def dns_status(self, project):
        configured = project.get("dns_workers")
        return {"workers": self.dns_workers if configured is None else configured,
                "inherited": configured is None}

    def deletion_blocker(self, project_id):
        """Called under the worker mutex again immediately before mutation."""
        project = self.store.get_project(project_id)
        if project is None:
            raise KeyError(project_id)
        latest = project.get("last_run")
        if latest and latest["status"] == "running":
            return "Stop this project's scan and wait for its worker to finish before deleting."
        for run_id, future in list(self._futures.items()):
            if not future.done():
                run = self.store.get_run(run_id)
                if run and run["project_id"] == project_id:
                    return "This project's scan worker is still shutting down. Wait a moment, then try again."
        return None

    def _cleanup_deleted_artifacts(self):
        """Remove only known run-owned paths; retry persisted failures on restart."""
        for run_id in self.store.pending_artifact_cleanup():
            try:
                if str(UUID(run_id)) != run_id:
                    raise ValueError("Invalid cleanup run identity")
                for folder, names in (("runs", [run_id]), ("progress", [run_id + ".json", run_id + ".log"])):
                    parent = self.data_dir / folder
                    if parent.is_symlink():
                        raise ValueError("Refusing cleanup through a symlinked artifact directory")
                    for name in names:
                        path = parent / name
                        if path.is_symlink():
                            path.unlink()
                        elif path.is_dir():
                            shutil.rmtree(path)
                        else:
                            path.unlink(missing_ok=True)
                self.store.finish_artifact_cleanup(run_id)
            except (OSError, ValueError):
                LOG.exception("Artifact cleanup pending for deleted report %s; will retry on restart", run_id)
        return len(self.store.pending_artifact_cleanup())

    def delete_project(self, project_id):
        with self._mutex:
            blocker = self.deletion_blocker(project_id)
            if blocker:
                raise RuntimeError(blocker)
            self.store.delete_project(project_id)
            return self._cleanup_deleted_artifacts()

    def delete_report(self, run_id):
        with self._mutex:
            run = self.store.get_run(run_id)
            if run is None:
                raise KeyError(run_id)
            blocker = self.deletion_blocker(run["project_id"])
            if blocker:
                raise RuntimeError(blocker)
            project_id = self.store.delete_report(run_id)
            return project_id, self._cleanup_deleted_artifacts()

    def discovery_status(self, project):
        return {"mode": project.get("discovery_mode", "enumerate"),
                "cached_available": self.store.has_candidate_inventory(project["id"]),
                "enumeration_enabled": self.discovery}

    def tool_status(self):
        tools = {}
        for label, package in (("AIL generator", "ail-typo-squatting"), ("DNS support", "dnspython")):
            try:
                tools[label] = {"available": True, "detail": metadata.version(package)}
            except metadata.PackageNotFoundError:
                tools[label] = {"available": False, "detail": f"Install requirements.txt ({package})."}
        backend = getattr(self.resolver, "name", type(self.resolver).__name__)
        tools[f"DNS lookups · {backend}"] = {
            "available": bool(getattr(self.resolver, "executable", None)) if isinstance(self.resolver, MassDnsResolver) else True,
            "detail": ("Requires rebuilt MassDNS 1.1.0+typowatch2 with JSON and resolver ownership fixes. " if isinstance(self.resolver, MassDnsResolver) else "")
                      + "Fresh A, AAAA and CNAME queries; no automatic backend fallback."}
        engines = getattr(self.discoverer, "engines", {"discovery": self.discoverer})
        for adapter in engines.values():
            engine = getattr(adapter, "name", type(adapter).__name__)
            version = getattr(adapter, "version", None)
            detail = f"Subdomain discovery{(' · CLI contract ' + version) if version else ''}"
            tools[engine] = {"available": self.discovery and bool(getattr(adapter, "executable", None)),
                             "detail": detail if self.discovery else "Discovery disabled for this server"}
        if self.capture_enabled:
            executable = bool(getattr(self.capturer, "executable", None))
            browser = bool(getattr(self.capturer, "chrome_path", None))
            tools["Gowitness captures"] = {"available": executable and browser,
                "detail": "HTTP and HTTPS visual evidence" if executable and browser else "Gowitness 3.2.2 and Chrome/Chromium are required."}
        else:
            tools["Gowitness captures"] = {"available": False, "detail": "Capture explicitly disabled for this server."}
        return tools

    def schedule_status(self, project):
        if project.get("schedules"):
            modes = project["schedules"]
            return {"modes": modes, "inherited": False,
                    "interval_hours": max(row["interval_hours"] for row in modes.values()),
                    "next_run_at": min((row["next_run_at"] for row in modes.values() if row["next_run_at"]), default=None)}
        configured = project.get("schedule_interval_hours")
        inherited = configured is None
        interval = self.interval_hours if inherited else configured
        next_run = None
        if interval > 0:
            if not inherited and project.get("schedule_next_run_at"):
                next_run = project["schedule_next_run_at"]
            else:
                latest = project.get("last_run")
                timestamp = ((latest.get("finished_at") if latest["status"] == "cancelled" else None)
                             or latest["started_at"]) if latest else project["created_at"]
                next_run = (datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                            + timedelta(hours=interval)).isoformat()
        mode = project.get("discovery_mode", "enumerate")
        modes = {key: {"capture_mode": project.get("capture_policy", {}).get("mode", "changes"),
                       "interval_hours": interval if key == mode else 0,
                       "next_run_at": next_run if key == mode else None} for key in ("enumerate", "cached")}
        return {"interval_hours": interval, "next_run_at": next_run, "inherited": inherited, "modes": modes}

    def _scheduled_mode(self, project, now=None):
        latest = project.get("last_run")
        if latest and (latest["status"] == "running" or "demo" in latest.get("source_status", {})):
            return None
        schedule = self.schedule_status(project)
        moment = now or datetime.now(timezone.utc)
        # Enumeration wins when both are due, satisfying both with one scan.
        for mode in ("enumerate", "cached"):
            row = schedule["modes"][mode]
            if (row["interval_hours"] and row["next_run_at"]
                    and datetime.fromisoformat(row["next_run_at"].replace("Z", "+00:00")) <= moment
                    and (mode != "cached" or self.store.has_candidate_inventory(project["id"]))):
                return mode
        return None

    def _schedule_due(self, project, now=None):
        return self._scheduled_mode(project, now) is not None

    def set_schedules(self, project_id, intervals, *, discovery_mode, capture_modes=None):
        with self._mutex:
            return self.store.set_schedules(project_id, intervals, discovery_mode=discovery_mode, capture_modes=capture_modes)

    def set_proxy_settings(self, project_id, changes):
        with self._mutex:
            return self.store.set_proxy_settings(project_id, changes)

    def set_capture_filter(self, project_id, *, enabled, rules):
        with self._mutex:
            return self.store.set_capture_filter(project_id, enabled=enabled, rules=rules)

    def set_global_capture_filter(self, *, enabled, rules):
        with self._mutex:
            return self.store.set_global_capture_filter(enabled=enabled, rules=rules)

    def set_capture_policy(self, project_id, *, mode, refresh_days):
        with self._mutex:
            return self.store.set_capture_policy(project_id, mode=mode, refresh_days=refresh_days)

    def _report_progress(self, run_id, stage, message=None, **values):
        reporter = self._progress.get(run_id)
        if reporter is None:
            return
        try:
            reporter.update(stage, message, **values)
        except Exception:
            # Diagnostics must never turn a valid DNS observation into failure.
            self._progress.pop(run_id, None)
            LOG.exception("Could not record live progress for %s", run_id)

    def submit_scan(self, project_id, *, discovery_mode=None, capture_mode=None, _scheduled=False):
        with self._mutex:
            if self._closed.is_set():
                raise RuntimeError("The scan worker is shutting down.")
            if not self.store.get_project(project_id):
                raise KeyError(project_id)
            project = self.store.get_project(project_id)
            # Re-read the deadline under the same lock as manual enqueueing.
            # A manual scan or changed schedule may have superseded the tick.
            if _scheduled:
                discovery_mode = self._scheduled_mode(project)
                if discovery_mode is None:
                    return None
                schedule = self.schedule_status(project)["modes"]
                capture_mode = schedule[discovery_mode].get("capture_mode", "changes")
                # A due full capture can be covered by the enumeration job too.
                if discovery_mode == "enumerate":
                    cached = schedule["cached"]
                    due = cached.get("next_run_at")
                    if (cached.get("interval_hours") and due and cached.get("capture_mode") == "full"
                            and datetime.fromisoformat(due) <= datetime.now(timezone.utc)):
                        capture_mode = "full"
            if project.get("last_run") and "demo" in project["last_run"].get("source_status", {}):
                raise RuntimeError("This is an offline simulated project. Create a separate project for real scans.")
            mode = Store._discovery_mode(project.get("discovery_mode", "enumerate")
                                         if discovery_mode is None else discovery_mode)
            if mode == "cached" and not self.store.has_candidate_inventory(project_id):
                raise ValueError("No saved candidate inventory yet. Run an enumeration scan first.")
            scope = self.resolver.comparison_scope() if hasattr(self.resolver, "comparison_scope") else {"resolver": "injected"}
            self.store.bind_comparison_scope(project_id, scope)
            from .proxy import public_settings, dns_route_key
            proxy_settings = self.store.proxy_settings(project_id)
            run = self.store.start_run(project_id, dns_workers=self.dns_status(project)["workers"],
                                       discovery_mode=mode, proxy_status=public_settings(proxy_settings),
                                       dns_route_key=dns_route_key(proxy_settings), capture_mode=capture_mode)
            self._proxy_snapshots[run["id"]] = proxy_settings
            requested = self._cancel_events[run["id"]] = threading.Event()
            try:
                self._progress[run["id"]] = RunProgress(self.data_dir, run["id"])
                self._report_progress(run["id"], "queued", "Queued; waiting for the scan worker.")
            except Exception:
                LOG.exception("Could not initialize live progress for %s", run["id"])
            try:
                self._futures[run["id"]] = self._executor.submit(self._execute, run)
                self.store.advance_schedule(project_id, discovery_mode=mode, capture_mode=run["capture_policy"]["mode"])
            except Exception as exc:
                requested.set()
                future = self._futures.get(run["id"])
                if future:
                    future.cancel()
                self.store.fail_run(run["id"], str(exc))
                self._report_progress(run["id"], "failed", f"Could not start the scan: {exc}", level="error")
                self._progress.pop(run["id"], None)
                self._proxy_snapshots.pop(run["id"], None)
                raise
            # Retain only outstanding work. History itself is durable in SQLite.
            self._futures = {key: future for key, future in self._futures.items() if not future.done()}
            return run

    def cancel_scan(self, run_id):
        with self._mutex:
            run = self.store.get_run(run_id)
            if run is None:
                raise KeyError(run_id)
            if run["status"] != "running":
                return run
            event = self._cancel_events.get(run_id)
            if event is not None:
                event.set()
            result = self.store.cancel_run(run_id)
            if result["status"] == "cancelled":
                self._report_progress(run_id, "cancelled", "Stopped by user; previously accepted results were kept.")
                self.store.advance_schedule(result["project_id"], discovery_mode=result.get("discovery_mode"),
                                            capture_mode=result.get("capture_policy", {}).get("mode"))
            future = self._futures.get(run_id)
            if future and future.cancel():
                self._futures.pop(run_id, None)
                self._cancel_events.pop(run_id, None)
                self._progress.pop(run_id, None)
                self._proxy_snapshots.pop(run_id, None)
            return result

    def scan_now(self, project_id, *, discovery_mode=None, capture_mode=None):
        run = self.submit_scan(project_id, discovery_mode=discovery_mode, capture_mode=capture_mode)
        with self._mutex:
            future = self._futures.get(run["id"])
        if future:
            try:
                future.result()
            except CancelledError:
                pass
        return self.store.get_run(run["id"])

    def _execute(self, run):
        run_id, project_id = run["id"], run["project_id"]
        workdir = self.data_dir / "runs" / run_id
        source_status = {}
        routes = ExitStack()
        proxy_settings = self._proxy_snapshots.get(run_id, {})
        requested = self._cancel_events[run_id]
        self._execution.cancel = requested
        def report(stage, message=None, **values):
            self._report_progress(run_id, stage, message, **values)

        signal = _CancellationSignal(self._closed, requested)
        workers = run.get("dns_workers") or self.dns_workers
        self.resolver.workers = workers
        if self.parking_classifier is not None:
            self.parking_classifier.workers = workers
        if self.capturer is not None:
            self.capturer.probe_workers = workers
            self.capturer.title_filter = run.get("capture_filter", {})
            self.capturer.capture_policy = run.get("capture_policy", {"mode": "full"})
            self.capturer.title_baselines = self.store.capture_baselines(project_id)
            self.capturer.baseline_root = self.data_dir
            self.capturer.capture_route = run.get("proxy_status", {}).get("capture", {})
            self.capturer.collect_titles = True
        from .proxy import direct_environment
        for adapter in (self.resolver, self.generator, self.discoverer, self.parking_classifier, self.capturer):
            if adapter is not None:
                adapter.cancel_event = signal
                adapter.run_id = run_id
                adapter.progress_callback = report
                adapter.workdir = workdir
                adapter.proxy_url = None
                adapter.proxy_environment = direct_environment()
                adapter.proxy_routes = None
        try:
            self._check_shutdown()
            workdir.mkdir(parents=True)
            project = self.store.get_project(project_id)
            old = self.store.inventory(project_id)
            mode = run.get("discovery_mode") or "enumerate"
            reuse_inventory = mode == "cached"
            engine = getattr(self.discoverer, "name", type(self.discoverer).__name__)
            if reuse_inventory:
                if not old["candidates"]:
                    raise ValueError("No saved candidate inventory yet. Run an enumeration scan first.")
                discovered = []
                source_status["discovery"] = {"status": "skipped", "engine": engine, "mode": mode,
                    "detail": "Using saved seeds and candidate inventory; no subdomain enumerators were started."}
                report("discovery", f"Using saved inventory: {len(old['seeds']):,} seeds and "
                       f"{len(old['candidates']):,} candidates. Subdomain enumeration and typo generation are skipped.")
            elif self.discovery:
                if proxy_settings.get("discovery", {}).get("enabled"):
                    from .proxy import HttpProxy, SocksEndpoint
                    route = HttpProxy(SocksEndpoint(proxy_settings["discovery"]["url"]))
                    routes.callback(route.close)
                    self.discoverer.proxy_url = route.url
                    self.discoverer.proxy_environment = route.environment()
                report("discovery", f"Discovering subdomains with {engine} for {len(project['roots'])} root domains.",
                       current=0, total=len(project["roots"]))
                LOG.info("Run %s: discovery starting with %s for %d roots", run_id, engine, len(project["roots"]))
                discovered, source_status["discovery"] = self.discoverer.discover(project["roots"], workdir)
                source_status["discovery"].setdefault("engine", engine)
            else:
                discovered = []
                source_status["discovery"] = {"status": "skipped", "engine": engine,
                                              "detail": "Discovery explicitly disabled; retained seeds still checked."}
            source_status["discovery"]["mode"] = mode
            # Enforce the discovery boundary independently of each tool's
            # parser. Raw Amass graph assets are never seeds or DNS evidence.
            # This scope restriction does not apply to generated typo domains,
            # which intentionally have names outside the client's roots.
            accepted, invalid_names, outside_scope = set(), 0, 0
            for value in discovered:
                try:
                    domain = normalize_domain(value)
                except ValueError:
                    invalid_names += 1
                    continue
                if not any(domain == root or domain.endswith("." + root) for root in project["roots"]):
                    outside_scope += 1
                    continue
                accepted.add(domain)
            discovered = sorted(accepted)
            source_status["discovery"].update(accepted_hostnames=len(discovered),
                rejected_invalid_names=invalid_names, rejected_out_of_scope=outside_scope)
            (workdir / "discovery-hostnames.txt").write_text(
                "".join(domain + "\n" for domain in discovered), encoding="utf-8")
            if not reuse_inventory:
                report("discovery", f"Accepted {len(discovered):,} unique in-scope discovery hostnames; "
                       "IP addresses and infrastructure assets cannot become seeds. Fresh DNS checks follow generation.",
                       metrics={"accepted_hostnames": len(discovered), "rejected_invalid_names": invalid_names,
                                "rejected_out_of_scope": outside_scope})
            seeds = sorted(set(project["roots"]) | set(old["seeds"]) | set(discovered))
            if self.capturer is not None:
                self.capturer.original_domains = set(seeds)
            self._check_shutdown()
            # Generation is deterministic per seed/profile. The candidate and
            # source inventory is already durable; only ungenerated seeds need
            # permutations. Unknown adapters must explicitly opt in to caching.
            signature_method = None if reuse_inventory else getattr(self.generator, "cache_signature", None)
            signature = signature_method() if callable(signature_method) else None
            if reuse_inventory:
                cached = set(seeds)
            else:
                cached = self.store.generation_cache(project_id, signature) if callable(signature_method) else set()
            pending = [seed for seed in seeds if seed not in cached]
            if not reuse_inventory:
                report("generation", f"Generating {len(pending)} seeds; reusing {len(seeds) - len(pending)} cached seeds.",
                       current=0, total=len(pending), metrics={"reused_seeds": len(seeds) - len(pending)})
                LOG.info("Run %s: generation starting for %d seeds; reusing %d", run_id, len(pending), len(seeds) - len(pending))
            generated, provenance, generation = [], {}, None
            if pending:
                generated, generator_status = self.generator.generate(pending, workdir)
                provenance = getattr(self.generator, "provenance", {})
                if signature is not None and generator_status.get("status") == "ok":
                    generation = {"signature": signature, "seeds": pending}
                generator_status = dict(generator_status)
                generator_status["detail"] = (generator_status.get("detail", "Permutation generation completed.")
                    + f" Generated {len(pending)} seeds; reused {len(seeds) - len(pending)} previously generated seeds.")
            else:
                generator_status = ({"status": "skipped", "detail": "Reused the saved candidate list without invoking AIL. "
                    "Choose enumeration to discover new seeds or apply a changed generation profile."} if reuse_inventory else
                    {"status": "ok", "detail": "All seeds were already generated with this profile; reused saved candidate inventory."})
            source_status["generator"] = {**generator_status, "generated_seeds": len(pending),
                                           "reused_seeds": len(seeds) - len(pending), "signature": signature}
            self._check_shutdown()
            # Never replace yesterday's search space with today's passive sample.
            candidates = sorted(set(old["candidates"]) | set(generated) | set(seeds))
            (workdir / "generation.json").write_text(json.dumps({"signature": signature, "generated_seeds": pending,
                "reused_seeds": [seed for seed in seeds if seed in cached], "seed_count": len(seeds),
                "generated_candidates": len(generated), "retained_candidates": len(old["candidates"]),
                "candidate_count": len(candidates), "candidate_limit": self.max_candidates,
                "discovery_mode": mode}, indent=2), encoding="utf-8")
            report("generation", (f"Reusing {len(candidates):,} saved candidate hostnames; fresh DNS checks follow."
                   if reuse_inventory else f"Generation finished for {len(pending):,} hostname seeds; "
                   f"{len(candidates):,} unique candidate hostnames await DNS checks."),
                   current=len(pending), total=len(pending), metrics={"seed_count": len(seeds),
                   "reused_seeds": len(seeds) - len(pending), "candidate_count": len(candidates),
                   "candidate_limit": self.max_candidates})
            if len(candidates) > self.max_candidates:
                raise RuntimeError(f"{len(candidates):,} candidate hostnames from {len(seeds):,} seeds exceed the configured "
                    f"{self.max_candidates:,} limit. These are unverified typo candidates, not resolving-domain counts. "
                    "Candidate DNS checks have not started. Review generation.json and discovery-hostnames.txt before raising "
                    "--max-candidates (TYPO_MAX_CANDIDATES in Compose); saved inventory and baseline were preserved.")
            (workdir / "candidates.txt").write_text("\n".join(candidates) + "\n", encoding="utf-8")
            backend = getattr(self.resolver, "name", type(self.resolver).__name__)
            if proxy_settings.get("dns", {}).get("enabled"):
                from .proxy import DnsRoutes, SocksEndpoint
                dns_routes = DnsRoutes(SocksEndpoint(proxy_settings["dns"]["url"]),
                                       self.resolver.comparison_scope()["nameservers"], cancel_event=signal)
                routes.callback(dns_routes.close)
                self.resolver.proxy_routes = dns_routes
                if self.parking_classifier is not None:
                    self.parking_classifier.proxy_routes = dns_routes
            if self.capturer is not None and proxy_settings.get("capture", {}).get("enabled"):
                from .proxy import HttpProxy, SocksEndpoint
                route = HttpProxy(SocksEndpoint(proxy_settings["capture"]["url"]))
                routes.callback(route.close)
                self.capturer.proxy_url = route.url
            source_status["network"] = {"status": "ok", "routes": run.get("proxy_status", {}),
                "detail": "Selected HTTP/DNS routes have no direct fallback on proxy failure. "
                          "A changed DNS route establishes a fresh DNS baseline on acceptance."}
            def resolve_candidates():
                try:
                    return self.resolver.resolve(candidates)
                except Exception as exc:
                    source_status["dns"] = {"status": "failed", "engine": backend,
                        "detail": getattr(self.resolver, "last_error", None) or f"{type(exc).__name__}: {exc}",
                        "version": getattr(self.resolver, "version", None),
                        "diagnostics": getattr(self.resolver, "last_diagnostics", {})}
                    raise
            LOG.info("Run %s: DNS checks starting with %s for %d candidates; concurrency %d", run_id, backend, len(candidates), workers)
            report("dns", f"Checking {len(candidates):,} domains with {backend}; DNS concurrency {workers}.",
                   current=0, total=len(candidates), metrics={"resolved": 0, "negative": 0, "uncertain": 0})
            overlapped_capture = None
            if (self.capturer is not None and getattr(self.resolver, "supports_result_stream", False)
                    and callable(getattr(self.capturer, "capture_stream", None))):
                from .scan_pipeline import CaptureOverlap
                pipeline = CaptureOverlap(self.resolver, self.capturer, candidates, workdir, signal, report)
                try:
                    report("pipeline", "Checking DNS; completed positive results feed HTTP checks and one browser process.",
                           current=0, total=len(candidates))
                    observations = resolve_candidates()
                    self._check_shutdown()
                    if set(observations) != set(candidates):
                        raise RuntimeError("Resolver did not return an observation for every candidate; baseline unchanged.")
                    try:
                        overlapped_capture = pipeline.finish(observations)
                    except Exception as exc:
                        self._check_shutdown()
                        LOG.exception("Could not finish overlapping capture for %s; retaining DNS observations", run_id)
                        from .scan_pipeline import _failed_rows
                        detail = f"Capture pipeline failed: {type(exc).__name__}: {exc}"
                        overlapped_capture = ({domain: _failed_rows(domain, detail)
                            for domain, item in observations.items() if item["status"] == "resolved"},
                            {"status": "failed", "detail": detail, "overlapped_dns": True})
                        report("pipeline", detail, level="error")
                finally:
                    pipeline.close()
            else:
                observations = resolve_candidates()
            self._check_shutdown()
            if set(observations) != set(candidates):
                raise RuntimeError("Resolver did not return an observation for every candidate; baseline unchanged.")
            dns_error = getattr(self.resolver, "last_error", None)
            source_status["dns"] = {
                "status": "failed" if getattr(self.resolver, "last_failure", False) else
                          "partial" if dns_error or any(o["status"] == "unknown" for o in observations.values()) else "ok",
                "engine": backend,
                "detail": "Fresh A, AAAA and CNAME; recursive DNS observations, not registration checks."
                          + (f" {dns_error}" if dns_error else ""),
                "nameservers": getattr(self.resolver, "nameservers", None) or "system",
                "workers": getattr(self.resolver, "workers", None),
                "diagnostics": getattr(self.resolver, "last_diagnostics", {})}
            if getattr(self.resolver, "version", None):
                source_status["dns"]["version"] = self.resolver.version
            if source_status["dns"]["status"] == "failed":
                for stage in ("parking", "screenshots", "visual_comparison"):
                    source_status[stage] = {"status": "skipped",
                        "detail": "DNS processing failed without a trustworthy complete domain result; this stage was not accepted."}
                raise RuntimeError(dns_error or "DNS processing failed; saved inventory and baseline were preserved.")
            if self.parking_classifier:
                LOG.info("Run %s: parking checks starting", run_id)
                report("parking", "Checking resolving domains for known DNS parking signals.")
                self.parking_classifier.nameservers = getattr(self.resolver, "nameservers", None)
                observations = self.parking_classifier.enrich(observations)
                self._check_shutdown()
                source_status["parking"] = {"status": "ok", "detail": "DNS parking indicators only; not a safety verdict or a website content check.",
                    "workers": workers,
                    "likely_parked": sum(o.get("parking", {}).get("status") == "likely_parked" for o in observations.values()),
                    "uncertain": sum(o.get("parking", {}).get("status") == "unknown" for o in observations.values() if o["status"] == "resolved")}
            (workdir / "observations.json").write_text(json.dumps(observations, indent=2), encoding="utf-8")
            (workdir / "provenance.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
            screenshots = None
            if self.capturer:
                resolving = sorted(domain for domain, observation in observations.items() if observation["status"] == "resolved")
                if overlapped_capture is None:
                    LOG.info("Run %s: website checks starting for %d resolving domains; screenshots only for responding HTTP/HTTPS endpoints", run_id, len(resolving))
                    report("websites", "Checking HTTP and HTTPS before browser capture.", current=0, total=len(resolving) * 2)
                try:
                    if overlapped_capture is not None:
                        screenshots, source_status["screenshots"] = overlapped_capture
                    else:
                        screenshots, source_status["screenshots"] = self.capturer.capture(resolving, workdir)
                except Exception as exc:
                    self._check_shutdown()
                    LOG.exception("Screenshot stage failed for %s; retaining DNS observations", run_id)
                    report("screenshots", f"Screenshot stage failed: {type(exc).__name__}: {exc}", level="error")
                    source_status["screenshots"] = {"status": "failed", "detail": f"{type(exc).__name__}: {exc}"}
                    now = datetime.now(timezone.utc).isoformat()
                    screenshots = {domain: [{"scheme": scheme, "url": f"{scheme}://{domain}",
                        "status": "failed", "relative_path": None, "title": None, "http_status": None,
                        "error": f"Capture stage failed: {type(exc).__name__}", "captured_at": now}
                        for scheme in ("http", "https")] for domain in resolving}
                self._check_shutdown()
                from .visuals import annotate_captures
                LOG.info("Run %s: local image comparison starting", run_id)
                report("comparison", "Comparing saved images with previous captures.")
                screenshots = annotate_captures(screenshots, workdir=workdir, data_dir=self.data_dir,
                    previous=lambda domain, scheme: self.store.latest_successful_capture(project_id, domain, scheme),
                    cancel_event=signal, progress_callback=report)
                source_status["visual_comparison"] = {"status": "ok", "detail": "Decoded pixel changes and HTTP/HTTPS similarity; local comparison, no AI requests.",
                    "changed": sum(row.get("visual", {}).get("change") == "changed" for rows in screenshots.values() for row in rows),
                    "duplicates": sum(bool(row.get("visual", {}).get("duplicate_of")) for rows in screenshots.values() for row in rows)}
                (workdir / "captures.json").write_text(json.dumps(screenshots, indent=2), encoding="utf-8")
            else:
                source_status["screenshots"] = {"status": "skipped", "detail": "Capture explicitly disabled or supplied test resolver has no capture adapter."}
            report("publishing", "Saving accepted observations, screenshots and change history.")
            with self._mutex:
                self._check_shutdown()
                result = self.store.finish_run(run_id, seeds=seeds, candidates=candidates,
                                               observations=observations, source_status=source_status, provenance=provenance,
                                               screenshots=screenshots, generation=generation)
            LOG.info("Run %s %s: %d candidates", run_id, result["status"], len(candidates))
            report(result["status"], "Scan finished; accepted results are available.", metrics=result.get("counts", {}))
            return result
        except Exception as exc:
            with self._mutex:
                current = self.store.get_run(run_id)
                if current["status"] != "running":
                    LOG.info("Run %s: %s; unaccepted partial work was not published", run_id, current["status"])
                    report(current["status"], "Scan stopped; unaccepted partial work was not published.")
                    return current
                if requested.is_set():
                    result = self.store.cancel_run(run_id)
                    report("cancelled", "Stopped by user; previously accepted results were kept.")
                    return result
                LOG.exception("Run %s failed", run_id)
                report("failed", f"{type(exc).__name__}: {exc}", level="error")
                return self.store.fail_run(run_id, f"{type(exc).__name__}: {exc}", source_status=source_status)
        finally:
            try:
                routes.close()
            except Exception:
                LOG.exception("Could not close all proxy relays for run %s", run_id)
            self._proxy_snapshots.pop(run_id, None)
            self._cancel_events.pop(run_id, None)
            self._progress.pop(run_id, None)
            self._execution.cancel = None
            if workdir.exists():
                try:
                    (workdir / "sources.json").write_text(json.dumps(source_status, indent=2), encoding="utf-8")
                except OSError:
                    LOG.exception("Could not write source diagnostics for %s", run_id)

    def _schedule(self):
        while not self._closed.is_set():
            self._schedule_tick()
            self._closed.wait(30)

    def _schedule_tick(self):
        for project in self.store.list_projects():
            if self._closed.is_set():
                return
            if self._schedule_due(project):
                try:
                    self.submit_scan(project["id"], _scheduled=True)
                except RuntimeError:
                    pass
                except Exception:
                    LOG.exception("Could not schedule project %s", project["id"])

    def _check_shutdown(self):
        if self._closed.is_set():
            raise RuntimeError("Scan interrupted by shutdown; accepted observations were preserved.")
        requested = getattr(self._execution, "cancel", None)
        if requested is not None and requested.is_set():
            raise RuntimeError("Scan cancelled by user; previously accepted observations were preserved.")

    def close(self):
        if self._closed.is_set():
            return
        self._closed.set()
        if self._scheduler:
            self._scheduler.join(timeout=2)
        with self._mutex:
            for run_id, future in self._futures.items():
                if future.cancel():
                    if self.store.get_run(run_id)["status"] == "running":
                        self.store.fail_run(run_id, "Server stopped before this queued scan began.")
                        self._report_progress(run_id, "failed", "Server stopped before this queued scan began.", level="error")
                    self._progress.pop(run_id, None)
                    self._proxy_snapshots.pop(run_id, None)
        self._executor.shutdown(wait=True)
        self._instance.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
