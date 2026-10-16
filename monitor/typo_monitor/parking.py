"""Optional DNS parking hints, kept separate from DNS change detection.

These narrowly scoped provider indicators are heuristics, not a safety verdict.
Only exact candidate NS answers and the candidate's existing CNAME records count.
"""

from concurrent.futures import ThreadPoolExecutor
from collections.abc import Mapping
import ipaddress
import math
import re

import dns.exception
import dns.resolver

from .domains import normalize_domain


# Provider-published parking endpoints; sources and limitations: docs/PARKING.md.
# GoDaddy's ordinary *.domaincontrol.com DNS is deliberately absent.
_NS_PROVIDERS = {
    "ns1.afternic.com": "Afternic",
    "ns2.afternic.com": "Afternic",
    "ns1.sedoparking.com": "Sedo",
    "ns2.sedoparking.com": "Sedo",
    "ns01.cashparking.com": "GoDaddy CashParking",
    "ns02.cashparking.com": "GoDaddy CashParking",
    "ns1.parkingcrew.net": "ParkingCrew",
    "ns2.parkingcrew.net": "ParkingCrew",
}
_PARKINGCREW_CNAME = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.parkingcrew\.net\Z", re.ASCII,
)


def _result(status, evidence, provider=None):
    return {"status": status, "provider": provider, "evidence": list(evidence)}


class ParkingClassifier:
    """Enrich resolved observations with conservative DNS-only parking hints.

    Each ``enrich`` call has a fresh exact-name lookup cache. The input's DNS
    statuses and RRsets are never changed, including when parking lookups fail.
    """

    def __init__(self, nameservers=None, lifetime=3, workers=12):
        if not math.isfinite(lifetime) or lifetime <= 0:
            raise ValueError("Parking DNS timeout must be positive and finite.")
        if not isinstance(workers, int) or isinstance(workers, bool) or not 1 <= workers <= 128:
            raise ValueError("Parking DNS workers must be between 1 and 128.")
        if isinstance(nameservers, str):
            raise ValueError("Parking nameservers must be a list of IP addresses.")
        self.nameservers = list(nameservers) if nameservers else None
        for server in self.nameservers or []:
            ipaddress.ip_address(server)
        self.lifetime, self.workers = lifetime, workers
        self.cancel_event = None

    def _check_shutdown(self):
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise RuntimeError("Parking enrichment canceled during shutdown.")

    @staticmethod
    def _cname_hint(domain, observation):
        targets = set()
        for record in observation.get("records", []):
            if isinstance(record, Mapping):
                kind, target = record.get("type"), record.get("value")
                owner = record.get("owner", record.get("name", domain))
                try:
                    if normalize_domain(owner) != domain:
                        continue
                except ValueError:
                    continue
            elif isinstance(record, (list, tuple)) and len(record) >= 2:
                kind, target = record[:2]
            else:
                continue
            if not isinstance(kind, str) or kind.upper() != "CNAME":
                continue
            try:
                target = normalize_domain(target)
            except ValueError:
                continue
            targets.add(target)
        matched = set()
        for target in targets:
            # This provider documents account-specific, one-label CNAME targets.
            # Its nameserver endpoints themselves are not parking CNAME targets.
            if (_PARKINGCREW_CNAME.fullmatch(target)
                    and target not in {"ns1.parkingcrew.net", "ns2.parkingcrew.net"}):
                matched.add(target)
        if matched:
            evidence = [f"CNAME {domain} -> {target}" for target in sorted(targets)]
            if matched != targets:
                return _result("unknown", evidence + ["Mixed CNAME evidence is insufficient to classify parking."])
            return _result("likely_parked", evidence, "ParkingCrew")
        return None

    def _lookup_ns(self, domain):
        self._check_shutdown()
        try:
            resolver = dns.resolver.Resolver()
            if self.nameservers:
                resolver.nameservers = self.nameservers
            resolver.lifetime = self.lifetime
            resolver.timeout = min(self.lifetime, 2)
            answer = resolver.resolve(domain, "NS", lifetime=self.lifetime,
                                      search=False, raise_on_no_answer=True)
            self._check_shutdown()
            rrset = answer.rrset
            # Recursive resolvers can follow aliases. Authority/parent NS and
            # NS returned for an alias target do not establish this child's use.
            if rrset is None or normalize_domain(str(rrset.name)) != domain:
                return _result("not_detected", [f"No NS answer owned by exact candidate {domain}."])
            targets = sorted({normalize_domain(value.to_text()) for value in answer})
        except dns.resolver.NoAnswer:
            return _result("not_detected", [f"No NS record at exact candidate {domain}."])
        except dns.resolver.NXDOMAIN:
            return _result("unknown", [f"NS lookup for {domain} returned NXDOMAIN after a successful DNS observation."])
        except (dns.exception.DNSException, OSError, ValueError) as error:
            return _result("unknown", [f"NS lookup for {domain} failed: {type(error).__name__}."])
        evidence = [f"NS {domain} -> {target}" for target in targets]
        matched = {_NS_PROVIDERS[target] for target in targets if target in _NS_PROVIDERS}
        if matched and len(matched) == 1 and all(target in _NS_PROVIDERS for target in targets):
            return _result("likely_parked", evidence, next(iter(matched)))
        if matched:
            return _result("unknown", evidence + ["Mixed nameserver evidence is insufficient to classify parking."])
        return _result("not_detected", evidence or [f"No NS record at exact candidate {domain}."])

    def enrich(self, observations):
        self._check_shutdown()
        if not isinstance(observations, dict):
            raise ValueError("Parking observations must be a domain mapping.")
        enriched, pending = {}, {}
        for original_domain, observation in observations.items():
            self._check_shutdown()
            if not isinstance(observation, dict):
                raise ValueError("Each DNS observation must be a mapping.")
            enriched[original_domain] = dict(observation)
            if observation.get("status") != "resolved":
                enriched[original_domain]["parking"] = _result(
                    "unknown", ["No current successful DNS observation; parking was not checked."],
                )
                continue
            try:
                domain = normalize_domain(original_domain)
            except ValueError:
                enriched[original_domain]["parking"] = _result("unknown", ["Invalid candidate name; parking was not checked."])
                continue
            hint = self._cname_hint(domain, observation)
            if hint is not None:
                enriched[original_domain]["parking"] = hint
            else:
                pending.setdefault(domain, []).append(original_domain)

        # Exact names are queried at most once per call. No cached parking hint
        # survives a subsequent run, so parked-to-active transitions stay visible.
        names = list(pending)
        with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="parking") as executor:
            for offset in range(0, len(names), self.workers * 4):
                self._check_shutdown()
                chunk = names[offset:offset + self.workers * 4]
                for domain, result in zip(chunk, executor.map(self._lookup_ns, chunk)):
                    for original_domain in pending[domain]:
                        enriched[original_domain]["parking"] = _result(
                            result["status"], result["evidence"], result["provider"],
                        )
        self._check_shutdown()
        return enriched
