"""Static layout/resource evidence for deciding whether prose needs a browser."""

import hashlib
from html.parser import HTMLParser
import json
from urllib.parse import urljoin, urldefrag


STRUCTURE_VERSION = "static-page-structure-v1"
STRUCTURE_STATUSES = frozenset({"complete", "unavailable", "budget"})
_ATTRS = frozenset({
    "id", "class", "style", "hidden", "role", "dir", "lang", "width", "height",
    "href", "src", "srcset", "sizes", "rel", "media", "integrity", "crossorigin",
    "action", "method", "enctype", "target", "formaction", "formmethod", "form",
    "type", "name", "required", "disabled", "readonly", "multiple", "checked",
    "selected", "pattern", "min", "max", "step", "sandbox", "srcdoc",
})
_URL_ATTRS = frozenset({"href", "src", "action", "formaction"})


class _Structure(HTMLParser):
    def __init__(self, url, check_budget):
        super().__init__(convert_charrefs=True)
        self.url, self.check_budget = url, check_budget
        self.digest = hashlib.sha256((STRUCTURE_VERSION + "\x00").encode())
        self.events = 0
        self.elements = 0
        self.raw = None
        self.raw_parts = []

    def _event(self, value):
        self.events += 1
        if self.events > 50000:
            raise ValueError("Static structure event limit reached")
        if self.events % 64 == 0 and self.check_budget:
            self.check_budget()
        self.digest.update(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode())
        self.digest.update(b"\x00")

    def handle_starttag(self, tag, attrs):
        self.elements += 1
        # Keep all selected attributes, not the report's truncated link/form
        # samples. Prose attributes, nonces and hidden field values are omitted.
        values = []
        refresh = tag == "meta" and any(k == "http-equiv" and (v or "").lower() == "refresh" for k, v in attrs)
        for name, value in attrs:
            if name not in _ATTRS and not (refresh and name in {"http-equiv", "content"}):
                continue
            if name in _URL_ATTRS and value:
                value = urldefrag(urljoin(self.url, value))[0]
            values.append((name, value))
        self._event(["open", tag, sorted(values, key=lambda item: (item[0], item[1] or ""))])
        if tag in {"script", "style"}:
            self.raw = tag
            self.raw_parts = []

    def handle_endtag(self, tag):
        if self.raw == tag:
            # Joining avoids chunk-boundary-dependent fingerprints. Script or
            # style edits remain meaningful even if extracted prose is stable.
            self._event(["raw", tag, "".join(self.raw_parts)])
            self.raw, self.raw_parts = None, []
        self._event(["close", tag])

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_decl(self, decl):
        self._event(["declaration", decl])

    def handle_data(self, data):
        if self.raw:
            self.raw_parts.append(data)


def structure_fingerprint(text, url, check_budget=None):
    """Ignore prose; retain element order, layout attributes, URLs and code.

    This is static markup evidence, not a rendered-layout or pixel comparison.
    The caller supplies strictly decoded, complete, byte-bounded HTML only.
    """
    if check_budget:
        check_budget()
    parser = _Structure(url or "", check_budget)
    parser.feed(text)
    parser.close()
    if check_budget:
        check_budget()
    if not parser.elements or parser.raw or parser.rawdata:
        raise ValueError("Incomplete static structure")
    return {"page_structure_sha256": parser.digest.hexdigest(),
            "page_structure_version": STRUCTURE_VERSION, "page_structure_status": "complete"}
