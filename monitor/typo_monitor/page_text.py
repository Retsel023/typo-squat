"""Bounded static HTML text, never browser execution or a rendered-DOM claim."""

import hashlib
from html.parser import HTMLParser
import json
import re
from urllib.parse import urljoin, urlsplit, urlunsplit


MAX_BODY_BYTES = 512 * 1024
MAX_TEXT_CHARS = 12000
EXTRACTION_VERSION = "static-text-v1"
TEXT_STATUSES = frozenset({"disabled", "complete", "missing", "sparse", "truncated", "non_html",
                           "encoded", "timeout", "read_error", "redirect_limit", "unsupported_redirect"})
_IGNORE = {"head", "script", "style", "noscript", "template", "svg", "title", "iframe"}
_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
_BLOCK = {"address", "article", "aside", "blockquote", "br", "dd", "div", "dl", "dt", "footer", "form",
          "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol", "p", "section", "table", "tr", "ul"}


class PageText(HTMLParser):
    def __init__(self, title, url):
        super().__init__(convert_charrefs=True)
        self.title, self.url = title, url
        self.stack, self.blocked, self.chunks, self.chars = [], 0, [], 0
        self.links, self.forms = set(), set()
        self.truncated = self.dynamic = self.done = False

    def _text(self, value):
        value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
        remaining = MAX_TEXT_CHARS - self.chars
        self.chunks.append(value[:remaining])
        self.chars += min(len(value), remaining)
        if len(value) > remaining:
            self.truncated = self.done = True

    def _url(self, value):
        try:
            target = urlsplit(urljoin(self.url, value))
            if target.scheme not in {"http", "https"} or not target.hostname or target.username is not None:
                return None
            target.port
            result = urlunsplit(target._replace(fragment=""))
            if len(result) > 2048:
                self.truncated = True
                return None
            return result
        except ValueError:
            self.truncated = True
            return None

    def _record(self, collection, value):
        if value:
            if len(collection) >= 512 and value not in collection:
                self.truncated = self.done = True
            else:
                collection.add(value)

    def handle_starttag(self, tag, attrs):
        self.title.handle_starttag(tag, attrs)
        if self.done:
            return
        attrs = dict(attrs)
        own_hidden = (tag in _IGNORE or "hidden" in attrs or (attrs.get("aria-hidden") or "").lower() == "true"
            or bool(re.search(r"(?:display\s*:\s*none|visibility\s*:\s*hidden)", attrs.get("style") or "", re.I)))
        hidden = self.blocked or own_hidden
        if tag in {"script", "iframe"}:
            self.dynamic = True
        if not hidden:
            if tag in _BLOCK:
                self._text("\n")
            if tag == "a" and attrs.get("href"):
                self._record(self.links, self._url(attrs["href"]))
            elif tag == "form":
                self._record(self.forms, "form " + (attrs.get("method") or "get").lower()[:20]
                             + " " + (self._url(attrs.get("action") or "") or "unknown action"))
            elif tag in {"input", "button", "select", "textarea"}:
                kind = (attrs.get("type") or tag).lower()[:40]
                if kind != "hidden":
                    # Values may contain tokens/user data. Keep field purpose only.
                    self._record(self.forms, "field " + kind + " " + (attrs.get("name") or "")[:120])
                    label = attrs.get("aria-label") or attrs.get("placeholder")
                    if label:
                        self._text(" " + " ".join(label.split()) + " ")
                    if tag == "input" and kind in {"submit", "button"}:
                        self._text(" " + " ".join((attrs.get("value") or "").split()) + " ")
        if tag not in _VOID:
            if len(self.stack) >= 256:
                self.truncated = self.done = True
                return
            self.stack.append((tag, own_hidden))
            self.blocked += bool(own_hidden)

    def handle_endtag(self, tag):
        self.title.handle_endtag(tag)
        if self.done:
            return
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                self.blocked -= sum(bool(hidden) for _, hidden in self.stack[index:])
                del self.stack[index:]
                break
        if not self.blocked and tag in _BLOCK:
            self._text("\n")
        if tag == "html":
            self.done = True

    def handle_data(self, value):
        self.title.handle_data(value)
        if not self.blocked and not self.done:
            self._text(re.sub(r"\s+", " ", value))

    def result(self, complete):
        text = "\n".join(line for value in "".join(self.chunks).splitlines() if (line := " ".join(value.split())))
        canonical = " ".join(text.split())
        status = ("truncated" if self.truncated or not complete else "read_error" if "\ufffd" in canonical else "missing" if not canonical else
                  "sparse" if self.dynamic and len(canonical) < 80 else "complete")
        links, forms = sorted(self.links), sorted(self.forms)
        fingerprint = json.dumps({"version": EXTRACTION_VERSION, "text": canonical, "links": links, "forms": forms},
                                 ensure_ascii=False, sort_keys=True)
        return {"content_status": status, "content_version": EXTRACTION_VERSION, "page_text": text,
                "text_sha256": hashlib.sha256(canonical.encode()).hexdigest() if status == "complete" else None,
                "content_sha256": hashlib.sha256(fingerprint.encode()).hexdigest() if status == "complete" else None,
                "forms_sha256": hashlib.sha256(json.dumps(forms, ensure_ascii=False).encode()).hexdigest() if status == "complete" else None,
                "links": [value[:256] for value in links[:8]], "forms": [value[:256] for value in forms[:8]],
                "links_count": len(links), "forms_count": len(forms)}
