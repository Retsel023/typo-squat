"""Static layout/resource evidence for deciding whether prose needs a browser."""

import hashlib
from collections import Counter
from html.parser import HTMLParser
import json
import re
from urllib.parse import urljoin, urldefrag


STRUCTURE_VERSION = "static-page-structure-v1"
STRUCTURE_STATUSES = frozenset({"complete", "unavailable", "budget"})
LAYOUT_VERSION = "static-layout-v1"
MAX_LAYOUT_FEATURES = 512
LAYOUT_MATCH_THRESHOLD = 0.95
_VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"})
_LAYOUT_ATTRS = frozenset({"class", "style", "hidden", "role", "dir", "width", "height", "colspan", "rowspan", "type"})
_FORM_ATTRS = frozenset({"action", "method", "enctype", "target", "formaction", "formmethod", "form", "type", "name",
                         "required", "disabled", "readonly", "multiple", "checked", "selected", "pattern", "min", "max", "step"})


def _hash(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()


def validate_layout(profile):
    """Bound persisted full-document evidence; absent legacy profiles are fine."""
    if profile is None:
        return
    if (not isinstance(profile, dict) or set(profile) != {"version", "features", "anchors_sha256", "nodes"}
            or profile["version"] != LAYOUT_VERSION or type(profile["nodes"]) is not int
            or not 1 <= profile["nodes"] <= 50000 or not isinstance(profile["anchors_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", profile["anchors_sha256"])):
        raise ValueError("Invalid static layout profile")
    features = profile["features"]
    if not isinstance(features, list) or not 1 <= len(features) <= MAX_LAYOUT_FEATURES:
        raise ValueError("Invalid static layout features")
    keys, total = [], 0
    for item in features:
        if (not isinstance(item, list) or len(item) != 2 or not isinstance(item[0], str)
                or not re.fullmatch(r"[0-9a-f]{24}", item[0]) or type(item[1]) is not int
                or not 1 <= item[1] <= 50000):
            raise ValueError("Invalid static layout feature")
        keys.append(item[0])
        total += item[1]
    if keys != sorted(set(keys)) or total != profile["nodes"]:
        raise ValueError("Incomplete static layout features")


def compare_layout(current, previous):
    """Compare complete structural multisets, independently of ordinary prose."""
    if current is None or previous is None:
        return None
    try:
        validate_layout(current)
        validate_layout(previous)
    except ValueError:
        return None
    a, b = dict(current["features"]), dict(previous["features"])
    intersection = sum(min(count, b.get(key, 0)) for key, count in a.items())
    union = current["nodes"] + previous["nodes"] - intersection
    similarity = intersection / union
    if current["anchors_sha256"] != previous["anchors_sha256"]:
        return {"matches": False, "reason": "key_elements_changed", "similarity": round(similarity * 100, 1)}
    # Short/generic documents need an exact structural match. For larger pages,
    # a few recommendations or wrapping tags must not create a whole new site.
    threshold = LAYOUT_MATCH_THRESHOLD if min(current["nodes"], previous["nodes"]) >= 40 and min(len(a), len(b)) >= 8 else 1
    matches = similarity >= threshold
    return {"matches": matches, "reason": "similar_layout" if matches else "layout_changed",
            "similarity": round(similarity * 100, 1)}


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
        self.layout_stack = []
        self.layout_features = Counter()
        self.layout_anchors = []
        self.layout_limited = False

    @staticmethod
    def _classes(value):
        # Common CMS content identifiers do not describe the site's layout.
        return " ".join(sorted(set(re.sub(r"\b(?:post|page-id|comment|menu-item|attachment)-\d+\b", "content-item", value).split())))

    def _layout_start(self, tag, attrs):
        attrs = dict(attrs)
        if "class" in attrs:
            attrs["class"] = self._classes(attrs["class"] or "")
        if len(attrs.get("class") or "") > 200 or any(len(value or "") > 2048 for key, value in attrs.items() if key in _LAYOUT_ATTRS):
            self.layout_limited = True
            return
        values = sorted((key, value) for key, value in attrs.items() if key in _LAYOUT_ATTRS)
        context = [item[1] for item in self.layout_stack[-4:]]
        feature = _hash([context, tag, values])[:24]
        self.layout_features[feature] += 1
        if len(self.layout_features) > MAX_LAYOUT_FEATURES:
            self.layout_features.pop(feature, None)
            self.layout_limited = True

        def target(name, default=""):
            return urldefrag(urljoin(self.url, attrs.get(name) or default))[0]

        article = tag == "article" or bool(self.layout_stack and self.layout_stack[-1][3])
        article = article or bool(re.search(r"(?:^|\s)(?:post|entry|article)-(?:content|card|item|header|footer)(?:\s|$)", attrs.get("class") or ""))
        navigation = (tag == "nav" and not article or attrs.get("role") == "navigation"
                      or bool(self.layout_stack and self.layout_stack[-1][2]))
        if (tag in {"html", "body", "main"} or tag in {"header", "nav", "footer"} and not article
                or attrs.get("role") in {"main", "banner", "navigation", "contentinfo"}):
            self.layout_anchors.append(["container", tag, values])
        if tag in {"form", "input", "button", "select", "textarea", "option"}:
            fields = {key: value for key, value in attrs.items() if key in _FORM_ATTRS}
            for key in ("action", "formaction"):
                if key in fields or tag == "form" and key == "action":
                    fields[key] = target(key)
            if tag == "form":
                fields["method"] = (fields.get("method") or "get").lower()
            if tag == "input":
                fields["type"] = (fields.get("type") or "text").lower()
            if tag == "option":
                fields["value"] = attrs.get("value")
            self.layout_anchors.append(["form", tag, sorted(fields.items())])
        elif tag == "a" and navigation and attrs.get("href"):
            self.layout_anchors.append(["navigation", target("href")])
        elif tag == "script" and attrs.get("src"):
            self.layout_anchors.append(["script", target("src"), attrs.get("integrity")])
        elif tag == "script":
            self.layout_anchors.append(["inline_script", attrs.get("type")])
        elif tag == "link" and set((attrs.get("rel") or "").lower().split()) & {"stylesheet", "icon", "apple-touch-icon"}:
            self.layout_anchors.append(["resource", target("href"), attrs.get("rel"), attrs.get("media")])
        elif tag == "base":
            self.layout_anchors.append(["base", target("href")])
        elif tag in {"iframe", "embed", "object"}:
            self.layout_anchors.append(["embedded", tag, target("src"), attrs.get("data"), attrs.get("srcdoc")])
        elif tag == "meta" and (attrs.get("http-equiv") or "").lower() == "refresh":
            self.layout_anchors.append(["refresh", attrs.get("content")])
        elif tag == "img" and re.search(r"\blogo\b", " ".join(attrs.get(key) or "" for key in ("id", "class", "alt", "itemprop")), re.I):
            self.layout_anchors.append(["brand_image", target("src"), attrs.get("srcset")])
        if tag not in _VOID:
            if len(self.layout_stack) >= 256:
                self.layout_limited = True
            else:
                label = tag + "." + (attrs.get("class") or "") + "." + (attrs.get("role") or "")
                self.layout_stack.append((tag, label, navigation, article))

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
        if not self.layout_limited:
            self._layout_start(tag, attrs)
        if tag in {"script", "style"}:
            self.raw = tag
            self.raw_parts = []

    def handle_endtag(self, tag):
        if self.raw == tag:
            # Joining avoids chunk-boundary-dependent fingerprints. Script or
            # style edits remain meaningful even if extracted prose is stable.
            self._event(["raw", tag, "".join(self.raw_parts)])
            if tag == "style":
                self.layout_anchors.append(["style", _hash("".join(self.raw_parts))])
            self.raw, self.raw_parts = None, []
        self._event(["close", tag])
        for index in range(len(self.layout_stack) - 1, -1, -1):
            if self.layout_stack[index][0] == tag:
                del self.layout_stack[index:]
                break

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_decl(self, decl):
        self._event(["declaration", decl])
        self.layout_anchors.append(["declaration", decl.lower()])

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
    profile = None if parser.layout_limited else {
        "version": LAYOUT_VERSION, "features": [[key, count] for key, count in sorted(parser.layout_features.items())],
        "anchors_sha256": _hash(parser.layout_anchors), "nodes": parser.elements}
    if check_budget:
        check_budget()
    return {"page_structure_sha256": parser.digest.hexdigest(), "page_layout": profile,
            "page_structure_version": STRUCTURE_VERSION, "page_structure_status": "complete"}
