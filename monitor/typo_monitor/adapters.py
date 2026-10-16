"""Bounded external discovery/generation and explicit DNS observation results."""

from concurrent.futures import ThreadPoolExecutor
from importlib.metadata import distribution, version
from pathlib import Path
import hashlib
import ipaddress
import json
import shutil
import subprocess
import sys
import time

from .domains import normalize_domain, parse_domains


def _run_command(args, *, cancel_event=None, timeout, **kwargs):
    if cancel_event is None:
        return subprocess.run(args, timeout=timeout, check=False, **kwargs)
    deadline = time.monotonic() + timeout
    with subprocess.Popen(args, **kwargs) as process:
        try:
            while True:
                if cancel_event.is_set():
                    raise RuntimeError("Scan canceled during shutdown; accepted observations were preserved.")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(args, timeout)
                try:
                    return subprocess.CompletedProcess(args, process.wait(timeout=min(0.25, remaining)))
                except subprocess.TimeoutExpired:
                    continue
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
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
        if lifetime <= 0 or not 1 <= workers <= 128:
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
        # executor.map bounds in-flight submissions on supported Python 3.10+ by
        # processing chunks; all candidates must receive an explicit observation.
        result = {}
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            for offset in range(0, len(candidates), self.workers * 4):
                if getattr(self, "cancel_event", None) is not None and self.cancel_event.is_set():
                    raise RuntimeError("DNS scan canceled during shutdown; accepted observations were preserved.")
                chunk = candidates[offset:offset + self.workers * 4]
                result.update(zip(chunk, executor.map(self.observe, chunk)))
        return result
