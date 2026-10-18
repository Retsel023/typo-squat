"""Fresh bulk DNS observations with the same comparison scope as DnsResolver.

The declared v1.1.0 JSON patch supplies wire-completeness metadata that stock
MassDNS omits. ``Je`` includes negative replies and terminal failures.
Every candidate must have an explicit result for A, AAAA and CNAME; absent
output is uncertainty. Raw packets' typed records are never reassigned to an
unrelated owner. A/AAAA may follow a verified answer-section CNAME chain, as
dnspython does, while the stored CNAME belongs only to the requested owner.

Schema source: https://github.com/blechschmidt/massdns/blob/v1.1.0/src/main.c
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import shutil
import signal
import stat
import struct
import subprocess
import threading
import time

from .adapters import DnsResolver, _report_progress, _run_command
from .domains import normalize_domain, normalize_records
from .progress import _clean_text, _open_read


LOG = logging.getLogger(__name__)
QUERY_TYPES = ("A", "AAAA", "CNAME")
MAX_CANDIDATES = 1_000_000
MAX_LINE_BYTES = 512 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024 * 1024
MAX_STDERR_BYTES = 16 * 1024 * 1024
MAX_POLL_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 8192
MAX_ALIAS_DEPTH = 32
_FLAGS = frozenset({"aa", "tc", "rd", "ra", "ad", "cd"})


class _UnsupportedMassDns(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class _Question:
    status: str
    records: tuple = ()
    error: str | None = None


_NOANSWER = _Question("noanswer")
_NXDOMAIN = _Question("nxdomain")


def _unknown(message, records=()):
    return _Question("unknown", tuple(records), str(message)[:500])


def _dns_name(value):
    import dns.name
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ValueError("Invalid DNS owner or target.")
    # These names come from the strictly decoded wire response, not MassDNS's
    # textual serializer, whose escape convention differs from DNS presentation.
    return dns.name.from_text(value).canonicalize().to_text().rstrip(".") or "."


def _responder(value, allowed):
    if not isinstance(value, str):
        return False
    if value.startswith("["):
        host, separator, port = value[1:].partition("]:")
    else:
        host, separator, port = value.rpartition(":")
    if not separator or not port.isdigit():
        return False
    try:
        host = str(ipaddress.ip_address(host))
        if isinstance(allowed, dict):
            return allowed.get(host) == int(port)
        return port == "53" and host in allowed
    except ValueError:
        return False


def _wire_answers(row, domain, query_type, metadata):
    """Validate actual DNS bytes locally; this performs no additional queries."""
    import dns.exception
    import dns.flags
    import dns.message
    import dns.opcode
    import dns.rcode
    import dns.rdataclass
    import dns.rdatatype

    encoded = metadata.get("wire_hex")
    if (not isinstance(encoded, str) or not 24 <= len(encoded) <= 65535 * 2
            or len(encoded) % 2):
        raise ValueError("Missing or oversized DNS wire payload.")
    wire = bytes.fromhex(encoded)
    if len(wire) * 2 != len(encoded):
        raise ValueError("Noncanonical DNS wire hex encoding.")
    response = dns.message.from_wire(wire, ignore_trailing=False, one_rr_per_rrset=True)
    if (not response.flags & dns.flags.QR or response.opcode() != dns.opcode.QUERY
            or response.flags & dns.flags.TC or len(response.question) != 1):
        raise ValueError("Not a complete standard DNS response.")
    question = response.question[0]
    if (_dns_name(question.name.to_text()) != domain or question.rdclass != dns.rdataclass.IN
            or question.rdtype != dns.rdatatype.from_text(query_type)):
        raise ValueError("DNS wire question does not match the requested domain and record type.")
    _, _, question_count, answer_count, authority_count, additional_count = struct.unpack("!6H", wire[:12])
    if (question_count != 1 or any(metadata[key] != count for key, count in (
            ("answer_count", answer_count), ("authority_count", authority_count),
            ("additional_count", additional_count)))):
        raise ValueError("DNS wire header counts do not match the output metadata.")
    flags = {name for name in _FLAGS if response.flags & getattr(dns.flags, name.upper())}
    if flags != set(row["flags"]):
        raise ValueError("DNS wire flags do not match the output metadata.")
    status = dns.rcode.to_text(response.rcode())
    if status != row.get("status"):
        raise ValueError("DNS wire response code does not match the output metadata.")
    answers = [{"name": rrset.name.to_text(), "type": dns.rdatatype.to_text(rrset.rdtype),
                "class": dns.rdataclass.to_text(rrset.rdclass), "data": record.to_text()}
               for rrset in response.answer for record in rrset]
    return status, answers


def _parse_reply(row, domain, query_type, nameservers):
    """Interpret a single validated question without trusting unrelated records."""
    if row.get("class") != "IN":
        return _unknown("Unexpected DNS question class.")
    if "error" in row:
        error = row["error"]
        if not isinstance(error, str) or not error or "status" in row:
            return _unknown("Malformed terminal failure record.")
        return _unknown(f"MassDNS terminal failure: {error[:100]}")
    metadata = row.get("typowatch")
    count_keys = ("answer_count", "authority_count", "additional_count")
    if (not isinstance(metadata, dict) or type(metadata.get("schema")) is not int
            or metadata["schema"] != 1 or type(metadata.get("complete")) is not bool or "wire_hex" not in metadata
            or any(type(metadata.get(key)) is not int or not 0 <= metadata[key] <= 65535 for key in count_keys)):
        raise _UnsupportedMassDns("MassDNS requires the bundled v1.1.0 Typo Watch JSON completeness patch; "
                                  "unpatched or incompatible output cannot be compared safely. No baseline was changed.")
    flags, data = row.get("flags"), row.get("data")
    if (not isinstance(flags, list) or any(not isinstance(flag, str) or flag not in _FLAGS for flag in flags)
            or len(flags) != len(set(flags)) or "tc" in flags):
        return _unknown("Missing, malformed or truncated DNS response flags.")
    if not _responder(row.get("resolver"), nameservers):
        return _unknown("DNS response is not from a configured resolver endpoint.")
    if row.get("proto") not in {"UDP", "TCP"}:
        return _unknown("Missing or unsupported DNS response protocol.")
    if (not isinstance(data, dict) or set(data) - {"answers", "authorities", "additionals"}
            or any(not isinstance(section, list) or len(section) > MAX_RECORDS for section in data.values())):
        return _unknown("Malformed DNS record sections.")
    if (not metadata["complete"] or any(len(data.get(section, [])) != metadata[key]
            for section, key in zip(("answers", "authorities", "additionals"), count_keys))):
        return _unknown("Incomplete DNS wire response or record-section count mismatch.")
    try:
        status, answers = _wire_answers(row, domain, query_type, metadata)
    except (ValueError, TypeError, UnicodeError, struct.error) as exc:
        return _unknown(f"DNS wire validation failed: {exc}")
    except Exception as exc:
        import dns.exception
        if isinstance(exc, dns.exception.DNSException):
            return _unknown(f"DNS wire validation failed: {type(exc).__name__}")
        raise
    if status == "NXDOMAIN":
        if answers:
            return _unknown("NXDOMAIN response also contains answer records.")
        return _NXDOMAIN
    if status != "NOERROR":
        return _unknown(f"DNS response code: {str(status)[:100]}")
    aliases, addresses, dnames = {}, {}, set()
    try:
        for record in answers:
            if (not isinstance(record, dict) or record.get("class") != "IN"
                    or not isinstance(record.get("type"), str)
                    or not isinstance(record.get("data"), str)):
                raise ValueError("Malformed answer record.")
            owner, kind = _dns_name(record.get("name")), record["type"]
            if kind == "CNAME":
                target = _dns_name(record["data"])
                if owner in aliases and aliases[owner] != target:
                    raise ValueError("Conflicting CNAME targets in one answer.")
                aliases[owner] = target
            elif kind in {"A", "AAAA"}:
                canonical = normalize_records([[kind, record["data"]]])[0][1]
                addresses.setdefault((owner, kind), set()).add(canonical)
            elif kind == "DNAME":
                _dns_name(record["data"])
                dnames.add(owner)
        current, visited = domain, set()
        for _ in range(MAX_ALIAS_DEPTH):
            if current in visited:
                raise ValueError("CNAME loop in answer.")
            visited.add(current)
            if current not in aliases:
                if any(current.endswith("." + owner) for owner in dnames):
                    raise ValueError("DNAME answer without an explicit validated CNAME chain.")
                break
            if any((current, kind) in addresses for kind in ("A", "AAAA")):
                raise ValueError("CNAME owner also has address records.")
            if query_type == "CNAME":
                # A CNAME query returns its owner's RRset, without substituting
                # any target's CNAME records into that RRset.
                return _Question("resolved", (("CNAME", aliases[domain]),))
            current = aliases[current]
        else:
            raise ValueError("CNAME chain exceeds the safe comparison limit.")
        records = {(query_type, value) for value in addresses.get((current, query_type), ())}
        if not records:
            return _NOANSWER
        if domain in aliases:
            records.add(("CNAME", aliases[domain]))
        return _Question("resolved", tuple(sorted(records)))
    except (ValueError, TypeError, UnicodeError) as exc:
        return _unknown(f"Invalid or incomplete DNS answer: {exc}")
    except Exception as exc:
        # DNS name parsing raises its own DNSException classes. Malformed tool
        # output cannot become a negative observation or invalidate old state.
        import dns.exception
        if isinstance(exc, dns.exception.DNSException):
            return _unknown(f"Invalid DNS name: {type(exc).__name__}")
        raise


def _observation(questions):
    records, failures, nxdomain, negatives = set(), [], 0, 0
    for query_type, question in zip(QUERY_TYPES, questions):
        if question is None:
            failures.append(f"{query_type}: no terminal result was produced")
            continue
        records.update(question.records)
        if question.status == "unknown":
            failures.append(f"{query_type}: {question.error or 'incomplete response'}")
        elif question.status in {"nxdomain", "noanswer"}:
            negatives += 1
            nxdomain += question.status == "nxdomain"
    if failures or nxdomain and nxdomain != len(QUERY_TYPES):
        return {"status": "unknown", "records": [], "partial_records": sorted(records),
                "error": "; ".join(failures) or "Inconsistent NXDOMAIN and other DNS answers"}
    if records:
        return {"status": "resolved", "records": sorted(records)}
    if negatives == len(QUERY_TYPES):
        return {"status": "nxdomain" if nxdomain else "noanswer", "records": []}
    return {"status": "unknown", "records": [], "error": "Incomplete DNS response"}


def _category(questions):
    if any(question is None for question in questions):
        return None
    status = _observation(questions)["status"]
    return "resolved" if status == "resolved" else "negative" if status in {"nxdomain", "noanswer"} else "uncertain"


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key.")
        result[key] = value
    return result


def _safe_path(path, *, directory=False):
    path = Path(path).absolute()
    if any(component.is_symlink() for component in (path, *path.parents)):
        raise ValueError("MassDNS artifacts cannot contain symlinks.")
    if path.exists() and (not path.is_dir() if directory else not path.is_file()):
        raise ValueError("Unexpected MassDNS artifact type.")
    return path


def _create(path):
    path = _safe_path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    return os.fdopen(descriptor, "wb")


def _stderr_summary(path):
    """Bounded diagnostic text, not DNS evidence or command instructions."""
    try:
        with _open_read(path) as stream:
            stream.seek(max(0, os.fstat(stream.fileno()).st_size - 4096))
            text = _clean_text(stream.read(4096).decode("utf-8", errors="replace"))
        lines = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("{")]
        return " | ".join(lines[-6:])[-1200:]
    except (OSError, ValueError):
        return ""


class _StopSignal:
    def __init__(self, external, local):
        self.external, self.local = external, local

    def is_set(self):
        return self.local.is_set() or self.external is not None and self.external.is_set()


class _OutputReader:
    def __init__(self, path, stderr, candidates, nameservers, stop, check_cancel, result_callback=None):
        self.path, self.stderr, self.stop = path, stderr, stop
        self.check_cancel = check_cancel
        self.questions = {domain: [None, None, None] for domain in candidates}
        self.nameservers = nameservers
        self.completed_questions = self.completed_domains = self.lines = self.offset = 0
        self.counts = {"resolved": 0, "negative": 0, "uncertain": 0}
        self.fatal = None
        self.unsupported = False
        self.result_callback = result_callback
        self.emitted = set()

    def reject(self, reason):
        self.fatal = reason
        self.stop.set()

    def poll(self, *, final=False):
        if self.fatal:
            return
        try:
            _safe_path(self.path)
            _safe_path(self.stderr)
            if self.path.stat().st_size > MAX_OUTPUT_BYTES or self.stderr.stat().st_size > MAX_STDERR_BYTES:
                self.reject("MassDNS output exceeded its storage safety limit.")
                return
            descriptor = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise ValueError("MassDNS output must be a regular file.")
                source.seek(self.offset)
                read_bytes = 0
                while final or read_bytes < MAX_POLL_BYTES:
                    position = source.tell()
                    line = source.readline(MAX_LINE_BYTES + 1)
                    if not line:
                        break
                    if len(line) > MAX_LINE_BYTES:
                        self.reject("MassDNS produced an oversized JSON record.")
                        return
                    if not line.endswith(b"\n"):
                        if final:
                            self.reject("MassDNS output ended with an incomplete JSON record.")
                        break
                    self.offset = source.tell()
                    read_bytes += self.offset - position
                    self.lines += 1
                    if self.lines % 1000 == 0:
                        self.check_cancel()
                    if self.lines > len(self.questions) * len(QUERY_TYPES) * 2 + 128:
                        self.reject("MassDNS produced too many duplicate or foreign records.")
                        return
                    try:
                        row = json.loads(line, object_pairs_hook=_unique_object)
                        if not isinstance(row, dict):
                            raise ValueError("Expected a JSON object.")
                        domain = normalize_domain(row.get("name"))
                        query_type = row.get("type")
                        if domain not in self.questions or query_type not in QUERY_TYPES:
                            raise ValueError("Unexpected DNS question name or type.")
                        question = _parse_reply(row, domain, query_type, self.nameservers)
                    except _UnsupportedMassDns as exc:
                        self.unsupported = True
                        self.reject(str(exc))
                        return
                    except (ValueError, TypeError, UnicodeError, RecursionError):
                        self.reject("Malformed or foreign MassDNS output; comparison remains uncertain.")
                        return
                    questions = self.questions[domain]
                    index = QUERY_TYPES.index(query_type)
                    previous = questions[index]
                    if previous == question:
                        continue
                    before = _category(questions)
                    if previous is None:
                        self.completed_questions += 1
                    else:
                        question = _unknown("Conflicting duplicate MassDNS results.",
                                            sorted(set(previous.records) | set(question.records)))
                    questions[index] = question
                    after = _category(questions)
                    if before is not None:
                        self.counts[before] -= 1
                    elif after is not None:
                        self.completed_domains += 1
                    if after is not None:
                        self.counts[after] += 1
                    if after == "resolved" and domain not in self.emitted and callable(self.result_callback):
                        self.emitted.add(domain)
                        # Early positives are provisional: contradictory later
                        # replies or a batch integrity failure can invalidate
                        # them. The service reconciles against resolve()'s final
                        # mapping before accepting any screenshot evidence.
                        try:
                            self.result_callback(domain, _observation(questions))
                        except Exception:
                            # Streaming is an optimization. The consumer also
                            # receives every final positive after the DNS batch,
                            # so failure here must not alter DNS evidence.
                            LOG.exception("Early DNS result consumer failed; deferring remaining captures")
                            self.result_callback = None
        except (OSError, ValueError) as exc:
            self.reject(f"MassDNS output could not be read: {type(exc).__name__}.")


class MassDnsResolver(DnsResolver):
    """One bounded MassDNS batch, retaining the existing resolver fingerprint.

    The service assigns ``workdir``, ``cancel_event``, ``run_id`` and an optional
    ``progress_callback`` for each run. No process starts until ``resolve``.
    ``lifetime`` is the approximate per-question retry budget; ``timeout`` is a
    hard wall-clock limit for the entire A/AAAA/CNAME subprocess.
    """

    name = "MassDNS"
    version = "1.1.0+typowatch2"
    supports_result_stream = True

    def __init__(self, nameservers=None, lifetime=4, workers=24, executable=None, *, resolve_count=3, timeout=3600,
                 resolver_mode="ordered"):
        super().__init__(nameservers=nameservers, lifetime=lifetime, workers=workers)
        if (not isinstance(resolve_count, int) or isinstance(resolve_count, bool) or not 1 <= resolve_count <= 10
                or not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
                or not math.isfinite(timeout) or not 0 < timeout <= 86400
                or lifetime > 3600):
            raise ValueError("MassDNS requires 1–10 attempts and positive bounded DNS/batch timeouts.")
        if resolver_mode not in {"ordered", "balanced"}:
            raise ValueError("Resolver mode must be ordered or balanced.")
        selected = executable or shutil.which("massdns")
        if selected:
            selected = shutil.which(str(selected)) or str(selected)
        self.executable = str(Path(selected).expanduser().absolute()) if selected else None
        self.resolve_count, self.timeout = resolve_count, timeout
        self.resolver_mode = resolver_mode
        self.workdir = None
        self.last_error = None
        self.last_failure = False
        self.last_diagnostics = {}

    def comparison_scope(self):
        scope = super().comparison_scope()
        # Existing ordered-mode baselines keep their original fingerprint.
        # A balanced pool changes the DNS view and must establish its own view.
        if self.resolver_mode == "balanced":
            scope["resolver_policy"] = "balanced-domain-sha256-v1"
        return scope

    def _check_cancel(self):
        signal = getattr(self, "cancel_event", None)
        if signal is not None and signal.is_set():
            raise RuntimeError("DNS scan cancelled during shutdown; accepted observations were preserved.")

    def resolve(self, candidates):
        self.last_error = None
        self.last_failure = False
        self.last_diagnostics = {"resolver_mode": self.resolver_mode}
        self._check_cancel()
        if not isinstance(self.workers, int) or isinstance(self.workers, bool) or not 1 <= self.workers <= 128:
            raise ValueError("DNS concurrency must be 1–128.")
        domains = list(dict.fromkeys(candidates))
        if len(domains) > MAX_CANDIDATES:
            raise RuntimeError("MassDNS candidate safety limit exceeded; inventory was not truncated.")
        if any(normalize_domain(domain) != domain for domain in domains):
            raise ValueError("MassDNS requires normalized candidate domains.")
        if not domains:
            return {}
        callback = getattr(self, "progress_callback", None)

        def unavailable(detail):
            self.last_error = detail
            self.last_failure = True
            _report_progress(callback, "dns", detail, current=0, total=len(domains),
                             metrics={"resolved": 0, "negative": 0, "uncertain": len(domains)}, level="warning")
            return {domain: {"status": "unknown", "records": [], "error": detail} for domain in domains}

        if not self.executable:
            return unavailable("MassDNS is unavailable; no fallback was used and all DNS checks remain uncertain.")
        try:
            if self.workdir is None:
                raise ValueError("No run artifact directory was supplied.")
            workdir = _safe_path(self.workdir, directory=True)
            if not workdir.is_dir():
                raise ValueError("Run artifact directory does not exist.")
            version_path = workdir / "massdns.version.txt"
            with _create(version_path) as version_log:
                version_result = _run_command([self.executable, "--version"], stdout=version_log,
                    stderr=subprocess.STDOUT, timeout=min(self.timeout, 10),
                    cancel_event=getattr(self, "cancel_event", None))
            self._check_cancel()
            with version_path.open("rb") as version_log:
                version_text = version_log.read(16 * 1024).decode("utf-8", errors="replace")
            if (version_result.returncode or "typowatch-json/1" not in version_text
                    or "safe-resolvers/1" not in version_text):
                return unavailable("MassDNS requires the rebuilt 1.1.0+typowatch2 binary with JSON validation and "
                    "safe-resolvers/1 ownership fixes; see massdns.version.txt. No DNS batch was started.")
            scope = self.comparison_scope()
            servers = {str(ipaddress.ip_address(server)) for server in scope["nameservers"]}
            # Preserve the preferred resolver order used by dnspython. Only
            # the exact pinned IPs also present in the resolver file are used.
            ordered_servers = list(dict.fromkeys(str(ipaddress.ip_address(server)) for server in self.nameservers))
            if self.resolver_mode == "balanced":
                ordered_servers = sorted(servers)
            if not servers:
                raise ValueError("No configured DNS resolvers are available.")
            if len(servers) > 16:
                raise ValueError("Configure at most 16 recursive DNS resolver IPs.")
            proxy_routes = getattr(self, "proxy_routes", None)
            if proxy_routes is not None:
                proxy_routes.check()
                ordered_servers = [proxy_routes.by_resolver[server] for server in ordered_servers]
                servers = dict(proxy_routes.ports)
            input_path, server_path = workdir / "massdns-input.txt", workdir / "massdns-resolvers.txt"
            output_path, stderr_path = workdir / "massdns.jsonl", workdir / "massdns.stderr.log"
            with _create(input_path) as target:
                for index, domain in enumerate(domains):
                    if index % 1000 == 0:
                        self._check_cancel()
                    selected = ordered_servers
                    if self.resolver_mode == "balanced":
                        offset = int.from_bytes(hashlib.sha256(domain.encode("ascii")).digest()[:8], "big") % len(selected)
                        selected = selected[offset:] + selected[:offset]
                    target.write((domain + " " + " ".join(selected) + "\n").encode("ascii"))
            with _create(server_path) as target:
                endpoints = proxy_routes.by_resolver.values() if proxy_routes is not None else sorted(servers)
                target.write(("\n".join(endpoints) + "\n").encode("ascii"))
            local_stop = threading.Event()
            reader = _OutputReader(output_path, stderr_path, domains, servers, local_stop, self._check_cancel,
                                   getattr(self, "result_callback", None))
            last_report = time.monotonic()

            def tick():
                nonlocal last_report
                if proxy_routes is not None:
                    try:
                        proxy_routes.check()
                    except RuntimeError:
                        reader.reject("SOCKS5 DNS relay failed; no direct fallback was used.")
                        return
                reader.poll()
                metrics = {**reader.counts, "queries_completed": reader.completed_questions,
                           "queries_total": len(domains) * len(QUERY_TYPES), "concurrency": self.workers}
                _report_progress(callback, "dns", current=reader.completed_domains,
                                 total=len(domains), metrics=metrics)
                if time.monotonic() - last_report >= 5:
                    LOG.info("Run %s: MassDNS %d/%d domains complete; %d/%d DNS questions finished",
                             getattr(self, "run_id", "manual"), reader.completed_domains, len(domains),
                             reader.completed_questions, len(domains) * len(QUERY_TYPES))
                    last_report = time.monotonic()

            interval = max(1, math.ceil(self.lifetime * 1000 / self.resolve_count))
            command = [str(self.executable), "-r", str(server_path), "-o", "Je",
                       "-t", "A", "-t", "AAAA", "-t", "CNAME", "-s", str(self.workers),
                       "-c", str(self.resolve_count), "-i", str(interval), "--verify-ip", "--flush", "--extended-input",
                       "--typowatch-json", "--typowatch-safe-resolvers",
                       "--status-format", "json", str(input_path)]
            _report_progress(callback, "dns", f"MassDNS checking all {len(domains):,} domains with {self.workers} simultaneous DNS questions.",
                             current=0, total=len(domains), metrics={"queries_completed": 0,
                             "queries_total": len(domains) * len(QUERY_TYPES), "concurrency": self.workers})
            command_error = None
            returncode = None
            with _create(output_path) as stdout, _create(stderr_path) as stderr:
                try:
                    result = _run_command(command, stdout=stdout, stderr=stderr, timeout=self.timeout,
                                          cancel_event=_StopSignal(getattr(self, "cancel_event", None), local_stop),
                                          on_tick=tick)
                    returncode = result.returncode
                    if result.returncode:
                        if result.returncode < 0:
                            try:
                                name = signal.Signals(-result.returncode).name
                            except ValueError:
                                name = f"signal {-result.returncode}"
                            self.last_diagnostics["signal"] = name
                            command_error = f"MassDNS terminated by {name} (status {result.returncode}); this is a process failure."
                        else:
                            command_error = f"MassDNS exited with status {result.returncode}."
                        summary = _stderr_summary(stderr_path)
                        command_error += f" {summary}" if summary else " See massdns.stderr.log."
                except subprocess.TimeoutExpired:
                    command_error = "MassDNS batch deadline exceeded; unfinished checks remain uncertain."
                except OSError as exc:
                    command_error = f"MassDNS could not run: {type(exc).__name__}."
                except RuntimeError:
                    self._check_cancel()
                    if not local_stop.is_set():
                        raise
            self._check_cancel()
            reader.poll(final=True)
            if reader.unsupported:
                self.last_error = reader.fatal
                self.last_failure = True
                raise RuntimeError(reader.fatal)
            error = reader.fatal or command_error
            self.last_error = error
            if error:
                _report_progress(callback, "dns", error, level="warning")
            observations = {}
            counts = {"resolved": 0, "negative": 0, "uncertain": 0}
            for index, (domain, questions) in enumerate(reader.questions.items()):
                if index % 1000 == 0:
                    self._check_cancel()
                if reader.fatal:
                    partial = sorted({record for question in questions if question is not None for record in question.records})
                    observation = {"status": "unknown", "records": [], "partial_records": partial, "error": reader.fatal}
                else:
                    observation = _observation(questions)
                    if command_error and observation["status"] == "unknown":
                        observation["error"] = f"{observation['error']}; {command_error}"
                observations[domain] = observation
                category = "resolved" if observation["status"] == "resolved" else "negative" if observation["status"] in {"nxdomain", "noanswer"} else "uncertain"
                counts[category] += 1
            trusted = len(domains) - counts["uncertain"]
            if not trusted:
                self.last_failure = True
                self.last_error = error or "No complete trustworthy DNS result was returned; all outcomes remain uncertain. Check resolver connectivity and massdns.stderr.log."
            self.last_diagnostics.update(returncode=returncode, completed_domains=reader.completed_domains,
                queries_completed=reader.completed_questions, queries_total=len(domains) * len(QUERY_TYPES),
                trustworthy_domains=trusted, unanswered_domains=len(domains) - reader.completed_domains)
            _report_progress(callback, "dns", current=reader.completed_domains, total=len(domains),
                             metrics={**counts, "queries_completed": reader.completed_questions,
                                      "queries_total": len(domains) * len(QUERY_TYPES), "concurrency": self.workers})
            LOG.info("Run %s: MassDNS %d/%d complete domain results; %d resolved, %d negative, %d uncertain",
                     getattr(self, "run_id", "manual"), reader.completed_domains, len(domains),
                     counts["resolved"], counts["negative"], counts["uncertain"])
            return observations
        except subprocess.TimeoutExpired:
            self._check_cancel()
            return unavailable("MassDNS version check exceeded its deadline; no DNS batch was started.")
        except (OSError, ValueError) as exc:
            self._check_cancel()
            return unavailable(f"MassDNS artifacts or resolver configuration are unavailable: {type(exc).__name__}.")
