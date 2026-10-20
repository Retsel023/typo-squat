"""Meaningful title evidence, separate from the original HTML/browser values."""

from functools import lru_cache
import re

from .domains import normalize_domain


MAX_TITLE_CHARS = 1024


@lru_cache(maxsize=4096)
def _address_pattern(domain):
    try:
        host = normalize_domain(domain).removeprefix("www.")
        hosts = {host, host.encode("ascii").decode("idna")}
    except (ValueError, UnicodeError):
        return None
    names = "|".join(re.escape(value) for value in sorted(hosts, key=len, reverse=True))
    # Match whole own-host tokens, including www, scheme, port and URL path.
    # Other hostnames and email addresses must retain their meaning.
    return re.compile(r"(?<![\w.@/-])(?:(?:https?:)?//)?(?:www\.)?(?:" + names
        + r")(?:\.(?![\w-]))?(?::[0-9]{1,5})?(?![\w.-])(?:[/?#][^\s|<>\"\[\](){}]*)?", re.IGNORECASE)


def comparison_title(title, domain):
    """Remove the scanned address while retaining meaningful title wording.

    A hostname/URL-only value is unavailable title evidence, not a changed
    title. Callers retain the raw observations for history and diagnostics.
    """
    if not isinstance(title, str) or len(title) > MAX_TITLE_CHARS:
        return None
    value = " ".join(title.split())
    pattern = _address_pattern(domain)
    if pattern is not None:
        value = pattern.sub("", value)
    value = " ".join(value.split()).strip(" -–—|:;·•/\\.,!?()[]{}<>\"'“”‘’")
    return value if any(char.isalnum() for char in value) else None
