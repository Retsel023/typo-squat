"""Bounded external discovery/generation and explicit DNS observation results."""

from contextlib import closing
from importlib.metadata import distribution, version
from pathlib import Path
import hashlib
import ipaddress
import json
import logging
import math
import os
import shutil
import signal
import subprocess
import sys
import time

from .domains import normalize_domain, parse_domains
from .concurrency import bounded_map

LOG = logging.getLogger(__name__)


def _report_progress(callback, stage, message=None, *, current=None, total=None, metrics=None, level="info"):
    """Telemetry is optional and cannot invalidate accepted adapter results."""
    if callable(callback):
        try:
            callback(stage, message, current=current, total=total,
                     metrics=dict(metrics) if metrics is not None else None, level=level)
        except Exception:
            LOG.debug("Progress callback failed for stage %s", stage, exc_info=True)


def _run_command(args, *, cancel_event=None, timeout, on_tick=None, **kwargs):
    if cancel_event is None and on_tick is None:
        return subprocess.run(args, timeout=timeout, check=False, **kwargs)
    deadline = time.monotonic() + timeout
    next_tick = time.monotonic() + 1
    groups = os.name == "posix"
    completed = False

    def tick():
        if callable(on_tick):
            try:
                on_tick()
            except Exception:
                LOG.debug("Command progress tick failed", exc_info=True)

    with subprocess.Popen(args, start_new_session=groups, **kwargs) as process:
        try:
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    raise RuntimeError("Scan cancelled or worker shutdown requested; accepted observations were preserved.")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(args, timeout)
                if on_tick is not None and time.monotonic() >= next_tick:
                    tick()
                    next_tick = time.monotonic() + 1
                try:
                    result = process.wait(timeout=min(0.25, remaining))
                    completed = result == 0
                    tick()
                    return subprocess.CompletedProcess(args, result)
                except subprocess.TimeoutExpired:
                    continue
        finally:
            if not completed:
                def stop(sig):
                    try:
                        if groups:
                            os.killpg(process.pid, sig)
                        elif process.poll() is None:
                            process.terminate() if sig == signal.SIGTERM else process.kill()
                    except ProcessLookupError:
                        pass
                stop(signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
                finally:
                    stop(signal.SIGKILL if groups else signal.SIGTERM)
                    if process.poll() is None:
                        process.kill()
                    process.wait()


class Subfinder:
    def __init__(self, executable=None, timeout=180):
        self.executable = executable or shutil.which("subfinder")
        self.timeout = timeout

    def discover(self, roots, workdir):
        if not self.executable:
            return [], {"status": "unavailable", "detail": "Subfinder unavailable; retained inventory is still checked."}
        found, errors = set(), []
        for index, root in enumerate(roots):
            log = Path(workdir) / f"subfinder-{index}.stderr.log"
            output = Path(workdir) / f"subfinder-{index}.txt"
            try:
                with output.open("w", encoding="utf-8") as stdout, log.open("w", encoding="utf-8") as stderr:
                    result = _run_command(
                        [self.executable, "-d", root, "-silent"],
                        stdout=stdout, stderr=stderr, timeout=self.timeout,
                        cancel_event=getattr(self, "cancel_event", None), text=True,
                    )
                # A timed-out/failed source may still have useful partial output.
                if result.returncode:
                    errors.append(f"{root}: exit {result.returncode}; see {log.name}")
            except (OSError, subprocess.TimeoutExpired) as exc:
                errors.append(f"{root}: {type(exc).__name__}")
            if output.exists():
                for raw in output.read_text(encoding="utf-8", errors="replace").splitlines():
                    try:
                        domain = normalize_domain(raw)
                    except ValueError:
                        continue
                    if domain == root or domain.endswith("." + root):
                        found.add(domain)
        return sorted(found), {
            "status": "partial" if errors else "ok",
            "detail": "; ".join(errors) if errors else "Passive discovery completed; absence is not evidence of removal.",
            "discovered": len(found),
        }


class AilGenerator:
    def __init__(self, timeout=900):
        self.timeout = timeout

    def cache_signature(self):
        """Fingerprint only inputs that can alter generated candidate names.

        Resource lookup uses package metadata without importing AIL or starting
        an extractor. Missing dependencies/data fail visibly rather than sharing
        a permissive fallback key with an older successful generation.
        """
        ail = distribution("ail-typo-squatting")
        suffixes = distribution("tldextract")
        resources = {
            "tldextract/.tld_set_snapshot": Path(suffixes.locate_file("tldextract/.tld_set_snapshot")),
            **{f"ail/{name}": Path(ail.locate_file(f"ail_typo_squatting/etc/{name}"))
               for name in ("common-misspellings.json", "homophones.txt", "tlds-alpha-by-domain.txt")},
        }
        profile = {
            "adapter_revision": 1,
            "algorithm": "runAll",
            "keep_original": True,
            "max_results": "unlimited",
            "suffix_source": "bundled; no online updates",
            "ail_version": ail.version,
            "tldextract_version": suffixes.version,
            "inflect_version": version("inflect"),
            "resources": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in resources.items()},
        }
        return hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def generate(self, seeds, workdir):
        self.provenance = {seed: [seed] for seed in seeds}
        workdir = Path(workdir)
        input_file = workdir / "seeds.txt"
        input_file.write_text("\n".join(sorted(seeds)) + "\n", encoding="utf-8")
        output = workdir / "generated"
        output.mkdir()
        log = workdir / "generator.log"
        with log.open("w", encoding="utf-8") as stream:
            result = _run_command(
                [sys.executable, "-m", "typo_monitor.generate", str(input_file), str(output)],
                cwd=Path(__file__).resolve().parent.parent,
                stdout=stream, stderr=subprocess.STDOUT, timeout=self.timeout,
                cancel_event=getattr(self, "cancel_event", None),
            )
        if result.returncode:
            raise RuntimeError(f"AIL generation failed (exit {result.returncode}); see {log}")
        candidates, invalid = set(seeds), 0
        for file in sorted(output.glob("*.txt")):
            seed = normalize_domain(file.stem)
            if seed not in seeds:
                raise RuntimeError("AIL output did not match the requested source seeds.")
            for line in file.read_text(encoding="utf-8").splitlines():
                try:
                    candidate = normalize_domain(line.strip())
                    candidates.add(candidate)
                    sources = self.provenance.setdefault(candidate, [])
                    if seed not in sources:
                        sources.append(seed)
                except ValueError:
                    # Some AIL transformations intentionally produce strings
                    # such as example-com. They are not public DNS hostnames.
                    invalid += 1
        if len(list(output.glob("*.txt"))) != len(seeds):
            raise RuntimeError("AIL did not produce an output file for every seed; no baseline was changed.")
        self.provenance = {domain: sorted(sources) for domain, sources in self.provenance.items()}
        return sorted(candidates), {"status": "ok", "version": version("ail-typo-squatting"), "invalid_generated_names": invalid, "detail": "AIL all algorithms, original domains retained; bundled suffix list. Invalid hostnames excluded."}


class DnsResolver:
    """Query A/AAAA/CNAME. An incomplete response cannot replace a full RRset."""

    def __init__(self, nameservers=None, lifetime=4, workers=24, resolver_factory=None):
        if (not math.isfinite(lifetime) or lifetime <= 0
                or not isinstance(workers, int) or isinstance(workers, bool)
                or not 1 <= workers <= 128):
            raise ValueError("DNS lifetime must be positive and workers must be 1–128.")
        self.nameservers = list(nameservers) if nameservers else None
        if self.nameservers:
            for server in self.nameservers:
                ipaddress.ip_address(server)
        self.lifetime, self.workers = lifetime, workers
        self.resolver_factory = resolver_factory

    def observe(self, domain):
        import dns.exception
        import dns.resolver
        import dns.rdatatype
        resolver = self.resolver_factory() if self.resolver_factory else dns.resolver.Resolver()
        if self.nameservers:
            resolver.nameservers = self.nameservers
        resolver.lifetime = self.lifetime
        resolver.timeout = min(self.lifetime, 2)
        records, failures, negatives = set(), [], 0
        nxdomain = 0
        for record_type in ("A", "AAAA", "CNAME"):
            if getattr(self, "cancel_event", None) is not None and self.cancel_event.is_set():
                raise RuntimeError("DNS check canceled during shutdown.")
            try:
                answer = resolver.resolve(domain, record_type, lifetime=self.lifetime, search=False, raise_on_no_answer=True)
                for value in answer:
                    records.add((record_type, value.to_text().rstrip(".").lower()))
                # Retain aliases belonging to the queried owner, never invent
                # findings for arbitrary CNAME targets in the response chain.
                for rrset in answer.response.answer:
                    if str(rrset.name).rstrip(".").lower() == domain and rrset.rdtype == dns.rdatatype.CNAME:
                        records.update(("CNAME", r.to_text().rstrip(".").lower()) for r in rrset)
            except dns.resolver.NXDOMAIN:
                nxdomain += 1
                negatives += 1
            except dns.resolver.NoAnswer:
                negatives += 1
            except (dns.exception.DNSException, OSError) as exc:
                failures.append(f"{record_type}: {type(exc).__name__}")
        if failures or (nxdomain and nxdomain != 3):
            return {"status": "unknown", "records": [], "partial_records": sorted(records), "error": "; ".join(failures) or "Inconsistent NXDOMAIN and positive answers"}
        if records:
            return {"status": "resolved", "records": sorted(records)}
        if negatives == 3:
            return {"status": "nxdomain" if nxdomain else "noanswer", "records": []}
        return {"status": "unknown", "records": [], "error": "Incomplete DNS response"}

    def comparison_scope(self):
        import dns.resolver
        # Pin the actual recursive servers for the life of this worker. A host
        # resolver configuration change must not silently change comparison view.
        if not self.nameservers:
            self.nameservers = [str(server) for server in dns.resolver.Resolver().nameservers]
        return {"nameservers": sorted(self.nameservers), "query_types": ["A", "AAAA", "CNAME"],
                "missing_threshold": 2, "semantics": 1}

    def resolve(self, candidates):
        result = {}
        counts = {"resolved": 0, "negative": 0, "uncertain": 0}
        last_report = time.monotonic()
        callback = getattr(self, "progress_callback", None)
        _report_progress(callback, "dns", current=0, total=len(candidates), metrics=counts)

        def check_cancel():
            if getattr(self, "cancel_event", None) is not None and self.cancel_event.is_set():
                raise RuntimeError("DNS scan canceled during shutdown; accepted observations were preserved.")

        with closing(bounded_map(self.observe, candidates, workers=self.workers,
                                 check_cancel=check_cancel, thread_name_prefix="dns")) as completed:
            for domain, observation in completed:
                result[domain] = observation
                status = observation["status"]
                counts["resolved" if status == "resolved" else "negative" if status in {"nxdomain", "noanswer"} else "uncertain"] += 1
                _report_progress(callback, "dns", current=len(result), total=len(candidates), metrics=counts)
                if time.monotonic() - last_report >= 5 or len(result) == len(candidates):
                    LOG.info("Run %s: DNS %d/%d checked; %d resolved, %d negative, %d uncertain",
                             getattr(self, "run_id", "manual"), len(result), len(candidates),
                             counts["resolved"], counts["negative"], counts["uncertain"])
                    last_report = time.monotonic()
        check_cancel()
        return result
