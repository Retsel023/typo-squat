"""Bounded full-HTML template fingerprints, ignoring only the current host."""

import hashlib
import re


TEMPLATE_VERSION = "self-host-html-v1"


def template_fingerprint(body, charset, hostname, *, url=None, title=None, check_budget=None):
    """Keep every other character meaningful; never normalize partial HTML."""
    empty = {"body_template_sha256": None, "body_template_version": None, "body_template_replacements": 0}
    if not hostname:
        return empty
    try:
        text = body.decode(charset, errors="strict")
    except (LookupError, UnicodeError):
        return empty
    # The placeholder cannot collide with literal page content.
    if "\x00" in text:
        return empty
    hostname = hostname.lower().rstrip(".")
    plain = hostname[4:] if hostname.startswith("www.") else hostname
    if not plain:
        return empty
    variants = sorted({plain, "www." + plain}, key=len, reverse=True)
    # Whole hostnames only: keep other hosts, parent domains, provider names,
    # unrelated URLs, prices, forms, scripts and styling meaningful.
    pattern = re.compile(r"(?<![\w.-])(?:" + "|".join(re.escape(value) for value in variants)
                         + r")(?:\.)?(?![\w.-])", re.IGNORECASE)
    normalized, count = pattern.subn("\x00OWN_HOST\x00", text)
    digest = hashlib.sha256((TEMPLATE_VERSION + "\x00" + normalized).encode("utf-8")).hexdigest()
    from .content_groups import main_content_fingerprint
    result = {"body_template_sha256": digest, "body_template_version": TEMPLATE_VERSION,
              "body_template_replacements": count}
    from .page_structure import structure_fingerprint
    try:
        result.update(structure_fingerprint(text, url, check_budget))
    except TimeoutError:
        result.update(page_structure_status="budget", body_content_group_status="budget")
        return result
    except (ValueError, RecursionError):
        result["page_structure_status"] = "unavailable"
    try:
        result.update(main_content_fingerprint(text, hostname, url, title, check_budget))
    except TimeoutError:
        result["body_content_group_status"] = "budget"
    except (ValueError, RecursionError):
        result["body_content_group_status"] = "unavailable"
    return result
