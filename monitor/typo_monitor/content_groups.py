"""Report-only main-content signatures; never capture or change decisions."""

import hashlib
from html.parser import HTMLParser
import json
import re

from .page_text import PageText


CONTENT_GROUP_VERSION = "main-content-consent-v1"
CONTENT_GROUP_STATUSES = frozenset({"unavailable", "complete", "truncated", "read_error", "missing",
                                    "sparse", "short", "unclosed_hidden_block", "budget"})
_CONTAINERS = {"div", "aside", "section", "dialog"}
_CONSENT_MARKERS = {
    "cookie-banner", "cookie-consent-banner", "cookie-consent", "cookieconsent",
    "cookie-notice", "cookie-notice-container", "cookie-law-info-bar", "cookie-law-info-again",
    "cky-consent-container", "cky-consent-bar", "cky-modal", "cky-btn-revisit-wrapper",
    "cmplz-cookiebanner", "cmplz-manage-consent", "onetrust-consent-sdk", "onetrust-banner-sdk",
    "cybotcookiebotdialog", "cybotcookiebotdialogbodyunderlay", "cookiebotwidget",
    "usercentrics-root", "uc-main-dialog", "cc-window", "osano-cm-window", "osano-cm-widget",
}


class _MainContent(PageText):
    def __init__(self, url, check_budget):
        super().__init__(HTMLParser(), url)
        self.consent_blocks = 0
        self.active_consent = None
        self.unclosed_consent = False
        self.check_budget, self.events = check_budget, 0

    def _budget(self):
        self.events += 1
        if self.events % 64 == 0 and self.check_budget:
            self.check_budget()

    def handle_starttag(self, tag, attrs):
        self._budget()
        values = dict(attrs)
        identifiers = {(values.get("id") or "").casefold(), *(values.get("class") or "").casefold().split()}
        if tag in _CONTAINERS and identifiers & _CONSENT_MARKERS:
            if not self.blocked:
                self.consent_blocks += 1
                self.active_consent = (len(self.stack) + 1, tag)
            attrs = [*attrs, ("hidden", "")]
        super().handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        self._budget()
        super().handle_endtag(tag)
        if self.active_consent and len(self.stack) < self.active_consent[0]:
            if tag != self.active_consent[1]:
                self.unclosed_consent = True
            self.active_consent = None
        # Do not drop an extra visible fragment following an early </html>.
        if tag == "html" and not self.truncated:
            self.done = False

    def handle_data(self, value):
        self._budget()
        super().handle_data(value)


def main_content_fingerprint(text, hostname, url, title, check_budget=None):
    empty = {"body_content_group_sha256": None, "body_content_group_main_sha256": None,
             "body_content_group_version": None,
             "body_content_group_ignored_consent": 0, "body_content_group_status": "unavailable"}
    if not hostname or not url:
        return empty
    labels = hostname.lower().rstrip(".").split(".")
    # Whole host/parent tokens down to two labels, for registry welcome pages
    # such as nl.gp versus nl.kg. This is not an ownership/registrability claim.
    names = {".".join(labels[index:]) for index in range(max(1, len(labels) - 1))}
    names.update("www." + name for name in tuple(names) if not name.startswith("www."))
    pattern = re.compile(r"(?<![\w.-])(?:" + "|".join(re.escape(name) for name in sorted(names, key=len, reverse=True))
                         + r")(?:\.)?(?![\w.-])", re.IGNORECASE)

    def normalize(value):
        result = pattern.sub("\x00PAGE_HOST\x00", value)
        for scheme, port in (("http", 80), ("https", 443)):
            result = re.sub(re.escape(f"{scheme}://\x00PAGE_HOST\x00:{port}") + r"(?=[/?#\s]|$)",
                            "//\x00PAGE_HOST\x00", result)
            result = result.replace(f"{scheme}://\x00PAGE_HOST\x00", "//\x00PAGE_HOST\x00")
        return " ".join(result.split())

    if check_budget:
        check_budget()
    parser = _MainContent(url, check_budget)
    parser.feed(text)
    parser.close()
    extracted = parser.result(True)
    # Never compare capped prefixes or short generic error/login messages.
    if extracted["content_status"] != "complete":
        empty["body_content_group_status"] = extracted["content_status"]
        return empty
    if parser.blocked or parser.active_consent or parser.unclosed_consent:
        empty["body_content_group_status"] = "unclosed_hidden_block"
        return empty
    canonical = normalize(extracted["page_text"])
    if len(canonical) < 120 or len(canonical.split()) < 15:
        empty["body_content_group_status"] = "short"
        return empty
    evidence = {"version": CONTENT_GROUP_VERSION, "text": canonical, "title": normalize(title or ""),
                "links": sorted({normalize(value) for value in parser.links}),
                "forms": sorted({normalize(value) for value in parser.forms})}
    digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, ensure_ascii=True).encode("ascii")).hexdigest()
    main_evidence = {key: value for key, value in evidence.items() if key != "title"}
    main_digest = hashlib.sha256(json.dumps(main_evidence, sort_keys=True, ensure_ascii=True).encode("ascii")).hexdigest()
    if check_budget:
        check_budget()
    return {"body_content_group_sha256": digest, "body_content_group_main_sha256": main_digest,
            "body_content_group_version": CONTENT_GROUP_VERSION,
            "body_content_group_ignored_consent": parser.consent_blocks, "body_content_group_status": "complete"}
