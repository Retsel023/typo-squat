"""Bounded HTML title/text checks and explicit, opt-in screenshot exclusions."""

import codecs
import hashlib
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
BODY_STATUSES = frozenset({"disabled", "complete", "empty", "truncated", "non_html", "encoded",
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


def inspect_title(response, session, deadline, check_cancel, *, collect_text=False):
    """Reuse the open response, with at most three extra redirect requests.

    A failed title lookup never retracts the initial HTTP response. Supported
    compression is decoded incrementally within the existing HTML byte limit.
    """
    result = {"title": None, "title_status": "missing", "title_url": response.url,
              "title_http_status": response.status_code, "title_bytes": 0,
              "content_status": "missing" if collect_text else "disabled",
              "body_sha256": None, "body_content_type": None, "body_status": "empty",
              "body_template_sha256": None, "body_template_version": None, "body_template_replacements": 0,
              "page_structure_sha256": None, "page_structure_version": None, "page_structure_status": "unavailable",
              "body_content_group_sha256": None, "body_content_group_main_sha256": None,
              "body_content_group_version": None,
              "body_content_group_ignored_consent": 0, "body_content_group_status": "unavailable"}
    title_parser = None

    def failed(status):
        result["title_status"] = status
        result["body_status"] = status
        result.update(body_sha256=None, body_template_sha256=None, body_template_version=None,
                      page_structure_sha256=None, page_structure_version=None, page_structure_status="unavailable",
                      body_template_replacements=0, body_content_group_sha256=None, body_content_group_main_sha256=None,
                      body_content_group_version=None, body_content_group_ignored_consent=0,
                      body_content_group_status="unavailable")
        if collect_text:
            result["content_status"] = status
        if title_parser is not None and title_parser.complete and not title_parser.truncated:
            title = " ".join(title_parser.text.split())
            if title:
                result.update(title=title, title_status="found")
        return result

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
                    result["title_url"] = None
                    return failed("unsupported_redirect")
                result.update(title_url=current.url, title_http_status=current.status_code)
                location = current.headers.get("Location")
                if current.status_code in {301, 302, 303, 307, 308} and location:
                    if hop == MAX_REDIRECTS:
                        return failed("redirect_limit")
                    if len(location) > 2048:
                        return failed("unsupported_redirect")
                    parsed = urlsplit(urljoin(current.url, location))
                    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                            or parsed.username is not None or parsed.password is not None):
                        return failed("unsupported_redirect")
                    parsed.port  # Reject malformed ports before requesting.
                    target = urlunsplit(parsed._replace(fragment=""))
                    if target in visited or len(target) > 2048:
                        return failed("redirect_limit")
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
                    return failed("non_html")
                encoding = current.headers.get("Content-Encoding", "identity").strip().lower()
                if encoding not in {"", "identity", "gzip", "x-gzip", "deflate"}:
                    return failed("encoded")
                from .html_body import HtmlBody
                body = HtmlBody(current.raw, encoding, remaining)
                charset = re.search(r"charset\s*=\s*[\"']?([^;\s\"']+)", content_type)
                charset_name = charset.group(1) if charset else "utf-8-sig"
                try:
                    decoder = codecs.getincrementaldecoder(charset_name)("replace")
                except LookupError:
                    charset_name = "utf-8-sig"
                    decoder = codecs.getincrementaldecoder(charset_name)("replace")
                title_parser = _Title()
                body_hash = hashlib.sha256()
                body_bytes = bytearray()
                result["body_content_type"] = content_type if len(content_type) <= 256 else None
                parser, limit, eof = title_parser, MAX_HTML_BYTES, False
                if collect_text:
                    from .page_text import MAX_BODY_BYTES, PageText
                    parser, limit = PageText(title_parser, current.url), MAX_BODY_BYTES
                # Text extraction can stop at its character/link/depth caps.
                # Continue hashing the response independently up to the HTML
                # byte cap/deadline, without feeding the stopped text parser.
                while result["title_bytes"] < limit:
                    remaining()
                    chunk = body.read(min(4096, limit - result["title_bytes"]))
                    remaining()
                    if not chunk:
                        if not parser.done and not parser.truncated:
                            parser.feed(decoder.decode(b"", final=True))
                            parser.close()
                        eof = True
                        break
                    result["title_bytes"] += len(chunk)
                    body_hash.update(chunk)
                    body_bytes.extend(chunk)
                    if not parser.done and not parser.truncated:
                        parser.feed(decoder.decode(chunk))
                title = " ".join(title_parser.text.split())
                result["title"] = title or None
                result["title_status"] = ("truncated" if title_parser.truncated or title_parser.inside and not title_parser.complete else "found" if title_parser.complete and title else
                    "truncated" if result["title_bytes"] == limit and not parser.done else "missing")
                if collect_text:
                    result.update(parser.result(eof or parser.done and not parser.truncated))
                # Only an actual end-of-body proves equality; a closed HTML
                # tag, readable text or a bounded prefix cannot establish it.
                if eof and result["title_bytes"]:
                    result["body_sha256"] = body_hash.hexdigest()
                    from .body_templates import template_fingerprint
                    try:
                        remaining()
                        result.update(template_fingerprint(body_bytes, charset_name, urlsplit(response.url).hostname,
                            url=current.url, title=result["title"], check_budget=remaining))
                    except TimeoutError:
                        # Optional fingerprints cannot retract a complete body.
                        # Without structure evidence, prose changes stay eligible.
                        result["page_structure_status"] = "budget"
                        result["body_content_group_status"] = "budget"
                result["body_status"] = "complete" if result["body_sha256"] else "empty" if eof else "truncated"
                return result
    except (TimeoutError, requests.exceptions.Timeout):
        return failed("timeout")
    except (requests.exceptions.RequestException, UrllibError, OSError, ValueError, UnicodeError):
        return failed("read_error")
    return result


def matching_rule(diagnostic, policy, *, original=False):
    if original or not policy.get("enabled") or diagnostic.get("title_status") != "found":
        return None
    title = (diagnostic.get("title") or "").casefold()
    return next((rule for rule in policy.get("rules", []) if rule.casefold() in title), None)


def filter_decision(diagnostic, policy, *, original=False):
    """Explain intentional bypasses separately from a literal non-match."""
    rule = matching_rule(diagnostic, policy, original=original)
    status = ("disabled" if not policy.get("enabled") else "original_reference" if original else
              "title_unavailable" if diagnostic.get("title_status") != "found" else
              "matched" if rule else "no_match")
    return {"status": status, "source": "html", "matched_rule": rule,
            "scope": rule_scope(rule, policy) if rule else None}
