"""Bounded HTML title checks and explicit, opt-in screenshot exclusions."""

import codecs
from contextlib import ExitStack
from html.parser import HTMLParser
import re
import time
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from urllib3.exceptions import HTTPError as UrllibError
from urllib3.util import Timeout


MAX_HTML_BYTES = 64 * 1024
MAX_TITLE_CHARS = 1024
MAX_REDIRECTS = 3
TITLE_STATUSES = frozenset({"disabled", "found", "missing", "truncated", "non_html", "encoded",
                            "timeout", "read_error", "redirect_limit", "unsupported_redirect"})


def normalize_policy(enabled=False, rules=()):
    if not isinstance(enabled, bool) or not isinstance(rules, (list, tuple)) or len(rules) > 50:
        raise ValueError("Use up to 50 title phrases, one per line.")
    result, seen = [], set()
    for rule in rules:
        if not isinstance(rule, str):
            raise ValueError("Title phrases must be text.")
        rule = rule.strip()
        if not rule:
            continue
        if len(rule) > 120 or any(ord(c) < 32 or ord(c) == 127 for c in rule):
            raise ValueError("Each title phrase must contain 1–120 printable characters.")
        if rule.casefold() not in seen:
            result.append(rule)
            seen.add(rule.casefold())
    if enabled and not result:
        raise ValueError("Enter at least one title phrase before enabling screenshot exclusions.")
    return {"enabled": enabled, "rules": result}


def combine_policies(global_policy, project_policy):
    """Snapshot both scopes and deduplicate enabled phrases, global first."""
    policies = {scope: normalize_policy(policy.get("enabled", False), policy.get("rules", []))
                for scope, policy in (("global", global_policy), ("project", project_policy))}
    rules, seen = [], set()
    for policy in policies.values():
        if policy["enabled"]:
            for rule in policy["rules"]:
                if rule.casefold() not in seen:
                    rules.append(rule)
                    seen.add(rule.casefold())
    return {"enabled": bool(rules), "rules": rules, **policies}


def rule_scope(rule, policy):
    """Keep the origin of an intentional skip in immutable capture metadata."""
    global_policy = policy.get("global", {})
    return "global" if global_policy.get("enabled") and any(
        value.casefold() == rule.casefold() for value in global_policy.get("rules", [])) else "project"


class _Title(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.inside = self.complete = self.done = self.truncated = False
        self.text = ""

    def handle_starttag(self, tag, attrs):
        if tag == "title" and not self.done:
            self.inside = True

    def handle_endtag(self, tag):
        if tag == "title" and self.inside:
            self.inside, self.complete, self.done = False, True, True
        elif tag == "head":
            self.done = True

    def handle_data(self, data):
        if self.inside and not self.done:
            remaining = MAX_TITLE_CHARS - len(self.text)
            self.text += data[:remaining]
            if len(data) > remaining:
                self.truncated = self.done = True


def inspect_title(response, session, deadline, check_cancel):
    """Reuse the open response, with at most three extra redirect requests.

    A failed title lookup never retracts the initial HTTP response. Compressed
    bodies are not decoded here, avoiding unbounded inflation before the byte cap.
    """
    result = {"title": None, "title_status": "missing", "title_url": response.url,
              "title_http_status": response.status_code, "title_bytes": 0}

    def remaining():
        check_cancel()
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError
        return value

    try:
        with ExitStack() as opened:
            current = response
            visited = {current.url}
            for hop in range(MAX_REDIRECTS + 1):
                remaining()
                if len(current.url) > 2048:
                    result.update(title_url=None, title_status="unsupported_redirect")
                    return result
                result.update(title_url=current.url, title_http_status=current.status_code)
                location = current.headers.get("Location")
                if current.status_code in {301, 302, 303, 307, 308} and location:
                    if hop == MAX_REDIRECTS:
                        result["title_status"] = "redirect_limit"
                        return result
                    if len(location) > 2048:
                        result["title_status"] = "unsupported_redirect"
                        return result
                    parsed = urlsplit(urljoin(current.url, location))
                    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                            or parsed.username is not None or parsed.password is not None):
                        result["title_status"] = "unsupported_redirect"
                        return result
                    parsed.port  # Reject malformed ports before requesting.
                    target = urlunsplit(parsed._replace(fragment=""))
                    if target in visited or len(target) > 2048:
                        result["title_status"] = "redirect_limit"
                        return result
                    visited.add(target)
                    # No redirect body is needed and no old connection is reused.
                    current.close()
                    for verify in (True, False):
                        budget = remaining()
                        try:
                            current = opened.enter_context(session.get(target, stream=True,
                                allow_redirects=False, verify=verify,
                                timeout=Timeout(total=budget, connect=budget, read=budget)))
                            break
                        except requests.exceptions.SSLError:
                            if not verify:
                                raise
                    continue

                content_type = current.headers.get("Content-Type", "").lower()
                if content_type and content_type.split(";", 1)[0].strip() not in {"text/html", "application/xhtml+xml"}:
                    result["title_status"] = "non_html"
                    return result
                if current.headers.get("Content-Encoding", "identity").strip().lower() not in {"", "identity"}:
                    result["title_status"] = "encoded"
                    return result
                charset = re.search(r"charset\s*=\s*[\"']?([^;\s\"']+)", content_type)
                try:
                    decoder = codecs.getincrementaldecoder(charset.group(1) if charset else "utf-8-sig")("replace")
                except LookupError:
                    decoder = codecs.getincrementaldecoder("utf-8-sig")("replace")
                parser = _Title()
                while result["title_bytes"] < MAX_HTML_BYTES and not parser.done:
                    remaining()
                    chunk = current.raw.read1(min(4096, MAX_HTML_BYTES - result["title_bytes"]), decode_content=False)
                    remaining()
                    if not chunk:
                        parser.feed(decoder.decode(b"", final=True))
                        break
                    result["title_bytes"] += len(chunk)
                    parser.feed(decoder.decode(chunk))
                title = " ".join(parser.text.split())
                result["title"] = title or None
                result["title_status"] = ("truncated" if parser.truncated else "found" if parser.complete and title else
                    "truncated" if result["title_bytes"] == MAX_HTML_BYTES and not parser.done else "missing")
                return result
    except (TimeoutError, requests.exceptions.Timeout):
        result["title_status"] = "timeout"
    except (requests.exceptions.RequestException, UrllibError, OSError, ValueError, UnicodeError):
        result["title_status"] = "read_error"
    return result


def matching_rule(diagnostic, policy, *, original=False):
    if (original or not policy.get("enabled") or diagnostic.get("title_status") != "found"
            or not 200 <= (diagnostic.get("title_http_status") or 0) < 300):
        return None
    title = (diagnostic.get("title") or "").casefold()
    return next((rule for rule in policy.get("rules", []) if rule.casefold() in title), None)
