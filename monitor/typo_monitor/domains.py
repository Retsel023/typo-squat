"""Strict, portable normalization for domain inputs and DNS record sets."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping


_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
_HOST_RECORDS = {"CNAME", "NS", "PTR", "DNAME"}


def normalize_domain(value: str) -> str:
    """Return a canonical ASCII domain, rejecting URLs, IPs and shell input.

    Surrounding whitespace is deliberately rejected here. The text-list parser
    handles whitespace and comments before calling this function.
    """
    if not isinstance(value, str) or not value or any(c.isspace() for c in value):
        raise ValueError("Enter a domain name without whitespace.")
    value = value[:-1] if value.endswith(".") else value
    try:
        domain = value.lower().encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError) as exc:
        raise ValueError(f"Invalid domain: {value!r}") from exc
    if len(domain) > 253 or "." not in domain:
        raise ValueError(f"Enter a full domain name: {value!r}")
    labels = domain.split(".")
    if not all(_LABEL.fullmatch(label) for label in labels) or labels[-1].isdigit():
        raise ValueError(f"Invalid domain: {value!r}")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError("IP addresses are not domain names.")


def parse_domains(text: str) -> list[str]:
    """Read one domain per line, supporting blank lines and # comments."""
    if not isinstance(text, str):
        raise ValueError("Domain input must be text.")
    result = set()
    for number, line in enumerate(text.splitlines(), start=1):
        value = line.partition("#")[0].strip()
        if not value:
            continue
        try:
            result.add(normalize_domain(value))
        except ValueError as exc:
            raise ValueError(f"Line {number}: {exc}") from exc
    return sorted(result)


def _dns_name(value: str) -> str:
    """Normalize DNS targets, which can legally include service labels/root."""
    if value == ".":
        return "."
    value = value.rstrip(".")
    try:
        return value.lower().encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid DNS record target.") from exc


def normalize_records(records: Iterable) -> list[list[str]]:
    """Canonicalize an RRset, ignoring ordering, duplicates and TTL metadata.

    The scanner uses [type, value] pairs. Dictionaries with type/value and
    optional owner/ttl metadata are also accepted for imported observations.
    TXT content is case-sensitive and is preserved exactly.
    """
    canonical = set()
    for record in records:
        if isinstance(record, Mapping):
            kind, value = record.get("type"), record.get("value")
        elif isinstance(record, (list, tuple)) and len(record) >= 2:
            kind, value = record[:2]
        else:
            raise ValueError("DNS records must contain a type and value.")
        if not isinstance(kind, str) or not isinstance(value, str):
            raise ValueError("DNS record types and values must be strings.")
        kind = kind.strip().upper()
        if not kind or not re.fullmatch(r"[A-Z0-9]+", kind):
            raise ValueError("Invalid DNS record type.")
        if kind == "TXT":
            canonical.add((kind, value))
            continue
        value = value.strip()
        if kind in {"A", "AAAA"}:
            try:
                address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError(f"Invalid {kind} record.") from exc
            if address.version != (4 if kind == "A" else 6):
                raise ValueError(f"Invalid {kind} address family.")
            value = str(address)
        elif kind in _HOST_RECORDS:
            value = _dns_name(value)
        elif kind in {"MX", "SRV", "SOA"}:
            fields = value.split()
            expected = {"MX": 2, "SRV": 4, "SOA": 7}[kind]
            if len(fields) != expected:
                raise ValueError(f"Invalid {kind} record.")
            if kind == "SOA":
                fields[:2] = [_dns_name(field) for field in fields[:2]]
            else:
                fields[-1] = _dns_name(fields[-1])
            value = " ".join(fields)
        canonical.add((kind, value))
    return [list(record) for record in sorted(canonical)]
