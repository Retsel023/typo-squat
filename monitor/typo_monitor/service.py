"""Single-process scan worker with durable inventory and isolated run artifacts."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
import json
import logging
import threading

from .adapters import AilGenerator, DnsResolver, Subfinder
from .domains import parse_domains
from .store import Store

LOG = logging.getLogger(__name__)


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
                 capture=True, capturer=None):
        if interval_hours < 0 or max_candidates < 1:
            raise ValueError("Schedule must be nonnegative and candidate limit positive.")
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._instance = InstanceLock(self.data_dir)
        try:
            self.store = Store(self.data_dir)
            self.store.recover_interrupted_runs()
        except Exception:
            self._instance.close()
            raise
        self.discovery = discovery
        self.resolver = resolver or DnsResolver()
        self.generator = generator or AilGenerator()
        self.discoverer = discoverer or Subfinder()
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
        self._closed = threading.Event()
        for adapter in (self.resolver, self.generator, self.discoverer):
            adapter.cancel_event = self._closed
        if self.parking_classifier:
            self.parking_classifier.cancel_event = self._closed
        if self.capturer:
            self.capturer.cancel_event = self._closed
        self._scheduler = None
        if interval_hours:
            self._scheduler = threading.Thread(target=self._schedule, daemon=True, name="schedule")
            self._scheduler.start()

    def create_project(self, name, roots):
        name = name.strip()
        if not name or len(name) > 120 or any(ord(c) < 32 for c in name):
            raise ValueError("Project name must contain 1–120 printable characters.")
        roots = parse_domains("\n".join(roots))
        if not roots or len(roots) > 500:
            raise ValueError("Enter between 1 and 500 root domains.")
        return self.store.create_project(name, roots)

    def tool_status(self):
        tools = {}
        for label, package in (("AIL generator", "ail-typo-squatting"), ("DNS resolver", "dnspython")):
            try:
                tools[label] = {"available": True, "detail": metadata.version(package)}
            except metadata.PackageNotFoundError:
                tools[label] = {"available": False, "detail": f"Install requirements.txt ({package})."}
        tools["Subfinder"] = {"available": bool(getattr(self.discoverer, "executable", None)), "detail": "Passive discovery" if self.discovery else "Discovery disabled for this server"}
        if self.capture_enabled:
            executable = bool(getattr(self.capturer, "executable", None))
            browser = bool(getattr(self.capturer, "chrome_path", None))
            tools["Gowitness captures"] = {"available": executable and browser,
                "detail": "HTTP and HTTPS visual evidence" if executable and browser else "Gowitness 3.2.2 and Chrome/Chromium are required."}
        else:
            tools["Gowitness captures"] = {"available": False, "detail": "Capture explicitly disabled for this server."}
        return tools

    def submit_scan(self, project_id):
        with self._mutex:
            if self._closed.is_set():
                raise RuntimeError("The scan worker is shutting down.")
            if not self.store.get_project(project_id):
                raise KeyError(project_id)
            project = self.store.get_project(project_id)
            if project.get("last_run") and "demo" in project["last_run"].get("source_status", {}):
                raise RuntimeError("This is an offline simulated project. Create a separate project for real scans.")
            scope = self.resolver.comparison_scope() if hasattr(self.resolver, "comparison_scope") else {"resolver": "injected"}
            self.store.bind_comparison_scope(project_id, scope)
            run = self.store.start_run(project_id)
            try:
                self._futures[run["id"]] = self._executor.submit(self._execute, run)
            except Exception as exc:
                self.store.fail_run(run["id"], str(exc))
                raise
            # Retain only outstanding work. History itself is durable in SQLite.
            self._futures = {key: future for key, future in self._futures.items() if not future.done()}
            return run

    def scan_now(self, project_id):
        run = self.submit_scan(project_id)
        with self._mutex:
            future = self._futures.get(run["id"])
        if future:
            future.result()
        return self.store.get_run(run["id"])

    def _execute(self, run):
        run_id, project_id = run["id"], run["project_id"]
        workdir = self.data_dir / "runs" / run_id
        source_status = {}
        try:
            workdir.mkdir(parents=True)
            project = self.store.get_project(project_id)
            old = self.store.inventory(project_id)
            if self.discovery:
                discovered, source_status["discovery"] = self.discoverer.discover(project["roots"], workdir)
            else:
                discovered = []
                source_status["discovery"] = {"status": "skipped", "detail": "Discovery explicitly disabled; retained seeds still checked."}
            seeds = sorted(set(project["roots"]) | set(old["seeds"]) | set(discovered))
            self._check_shutdown()
            # Generation is deterministic per seed/profile. The candidate and
            # source inventory is already durable; only ungenerated seeds need
            # permutations. Unknown adapters must explicitly opt in to caching.
            signature_method = getattr(self.generator, "cache_signature", None)
            signature = signature_method() if callable(signature_method) else None
            cached = self.store.generation_cache(project_id, signature) if callable(signature_method) else set()
            pending = [seed for seed in seeds if seed not in cached]
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
                generator_status = {"status": "ok", "detail": "All seeds were already generated with this profile; reused saved candidate inventory."}
            source_status["generator"] = {**generator_status, "generated_seeds": len(pending),
                                           "reused_seeds": len(seeds) - len(pending), "signature": signature}
            (workdir / "generation.json").write_text(json.dumps({"signature": signature, "generated_seeds": pending,
                "reused_seeds": [seed for seed in seeds if seed in cached]}, indent=2), encoding="utf-8")
            self._check_shutdown()
            # Never replace yesterday's search space with today's passive sample.
            candidates = sorted(set(old["candidates"]) | set(generated) | set(seeds))
            if len(candidates) > self.max_candidates:
                raise RuntimeError(f"{len(candidates):,} candidates exceed the configured {self.max_candidates:,} limit. Increase --max-candidates; inventory was not truncated.")
            (workdir / "candidates.txt").write_text("\n".join(candidates) + "\n", encoding="utf-8")
            observations = self.resolver.resolve(candidates)
            self._check_shutdown()
            if set(observations) != set(candidates):
                raise RuntimeError("Resolver did not return an observation for every candidate; baseline unchanged.")
            source_status["dns"] = {"status": "partial" if any(o["status"] == "unknown" for o in observations.values()) else "ok", "detail": "A, AAAA and CNAME; recursive DNS observations, not registration checks.", "nameservers": getattr(self.resolver, "nameservers", None) or "system", "workers": getattr(self.resolver, "workers", None)}
            if self.parking_classifier:
                self.parking_classifier.nameservers = getattr(self.resolver, "nameservers", None)
                observations = self.parking_classifier.enrich(observations)
                self._check_shutdown()
                source_status["parking"] = {"status": "ok", "detail": "DNS parking indicators only; not a safety verdict or a website content check.",
                    "likely_parked": sum(o.get("parking", {}).get("status") == "likely_parked" for o in observations.values()),
                    "uncertain": sum(o.get("parking", {}).get("status") == "unknown" for o in observations.values() if o["status"] == "resolved")}
            (workdir / "observations.json").write_text(json.dumps(observations, indent=2), encoding="utf-8")
            (workdir / "provenance.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
            screenshots = None
            if self.capturer:
                resolving = sorted(domain for domain, observation in observations.items() if observation["status"] == "resolved")
                try:
                    screenshots, source_status["screenshots"] = self.capturer.capture(resolving, workdir)
                except Exception as exc:
                    self._check_shutdown()
                    LOG.exception("Screenshot stage failed for %s; retaining DNS observations", run_id)
                    source_status["screenshots"] = {"status": "failed", "detail": f"{type(exc).__name__}: {exc}"}
                    now = datetime.now(timezone.utc).isoformat()
                    screenshots = {domain: [{"scheme": scheme, "url": f"{scheme}://{domain}",
                        "status": "failed", "relative_path": None, "title": None, "http_status": None,
                        "error": f"Capture stage failed: {type(exc).__name__}", "captured_at": now}
                        for scheme in ("http", "https")] for domain in resolving}
                self._check_shutdown()
                from .visuals import annotate_captures
                screenshots = annotate_captures(screenshots, workdir=workdir, data_dir=self.data_dir,
                    previous=lambda domain, scheme: self.store.latest_successful_capture(project_id, domain, scheme))
                source_status["visual_comparison"] = {"status": "ok", "detail": "Decoded pixel changes and HTTP/HTTPS similarity; local comparison, no AI requests.",
                    "changed": sum(row.get("visual", {}).get("change") == "changed" for rows in screenshots.values() for row in rows),
                    "duplicates": sum(bool(row.get("visual", {}).get("duplicate_of")) for rows in screenshots.values() for row in rows)}
                (workdir / "captures.json").write_text(json.dumps(screenshots, indent=2), encoding="utf-8")
            else:
                source_status["screenshots"] = {"status": "skipped", "detail": "Capture explicitly disabled or supplied test resolver has no capture adapter."}
            result = self.store.finish_run(run_id, seeds=seeds, candidates=candidates,
                                           observations=observations, source_status=source_status, provenance=provenance,
                                           screenshots=screenshots, generation=generation)
            LOG.info("Run %s %s: %d candidates", run_id, result["status"], len(candidates))
            return result
        except Exception as exc:
            LOG.exception("Run %s failed", run_id)
            return self.store.fail_run(run_id, f"{type(exc).__name__}: {exc}")
        finally:
            if workdir.exists():
                try:
                    (workdir / "sources.json").write_text(json.dumps(source_status, indent=2), encoding="utf-8")
                except OSError:
                    LOG.exception("Could not write source diagnostics for %s", run_id)

    def _schedule(self):
        # Inspect persisted last attempt times; restart does not create a new
        # cadence or repeatedly enqueue failed/partial projects every minute.
        while not self._closed.is_set():
            now = datetime.now(timezone.utc)
            for project in self.store.list_projects():
                latest = project.get("last_run")
                if latest and "demo" in latest.get("source_status", {}):
                    continue
                if latest and latest["status"] == "running":
                    continue
                timestamp = latest["started_at"] if latest else project["created_at"]
                elapsed = (now - datetime.fromisoformat(timestamp.replace("Z", "+00:00"))).total_seconds()
                if elapsed >= self.interval_hours * 3600:
                    try:
                        self.submit_scan(project["id"])
                    except RuntimeError:
                        pass
                    except Exception:
                        LOG.exception("Could not schedule project %s", project["id"])
            self._closed.wait(30)

    def _check_shutdown(self):
        if self._closed.is_set():
            raise RuntimeError("Scan interrupted by shutdown; accepted observations were preserved.")

    def close(self):
        if self._closed.is_set():
            return
        self._closed.set()
        if self._scheduler:
            self._scheduler.join(timeout=2)
        with self._mutex:
            for run_id, future in self._futures.items():
                if future.cancel():
                    self.store.fail_run(run_id, "Server stopped before this queued scan began.")
        self._executor.shutdown(wait=True)
        self._instance.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
