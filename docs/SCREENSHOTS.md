# HTTP and HTTPS screenshots

Gowitness screenshots support visual review of currently resolving candidates. Each domain gets independent HTTP and HTTPS checks on ports 80 and 443 before a browser is launched. Only endpoints that return an HTTP response are submitted to Gowitness. DNS-resolving domains stay in the inventory even when neither endpoint responds. Parking classification does not prevent capture. Images are evidence for a reviewer; the application does not infer impersonation or safety from a screenshot.

The preflight reuses a lightweight streamed GET for bounded static title/text extraction (up to 512 KiB of HTML and 12,000 text characters in default text mode; 64 KiB in title-only mode). Redirects and error responses such as 403, 404 and 500 still count as web responses; requiring HTTP 200 or using only HEAD would miss real sites. Static checks follow at most three HTTP redirects within the same timeout budget; the browser independently follows redirects when capture is needed. Checks use bounded parallel workers and a configurable `--web-timeout` (default 3 seconds). A certificate error triggers a second check within the remaining timeout budget, retaining the TLS diagnostic; this is evidence collection without login credentials. A timeout is uncertain, not proof that no website exists. `preflight.json` retains per-endpoint diagnostics. Checks run again on every scan, including previously unreachable endpoints.

Global/project title exclusions apply to both full and change-only scans. A
matching complete HTML title skips Gowitness even on HTTP error responses.
Bounded gzip/zlib-deflate decoding and a shared browser user-agent improve the
pre-browser check. Rendered Gowitness titles are checked again after capture;
those matches are excluded from reports, the normal gallery and AI, while the
already-created image remains in manual history. Pre-browser skips and
post-capture exclusions have separate counts. Missing/unreadable titles remain
eligible, and original references bypass title exclusions.

**Live output → capture-decisions.log** explains each endpoint's browser
selection alongside `gowitness.log`. `before_browser` records the fetched HTML
title, read status, filter decision and reason for selecting or skipping
Gowitness. `browser_reported` records the rendered title/filter while the scan is
still running; its screenshot flag is provisional until artifact validation.
`verified_result` records whether a valid image was actually saved and whether
the browser title caused a later report exclusion. A selected URL is not proof
of a capture, and `have-screenshot=true` in Gowitness output is not proof that
the application accepted its artifact or included it in a report.

The decision log is recent local telemetry, capped at 2 MiB with older entries
trimmed. It contains bounded metadata, not page bodies or proxy credentials.
The UI still reads only a bounded tail. Complete accepted observations remain
in saved capture history. Logging does not alter exclusions or prevent a
browser-only title's first capture; the earlier HTML result is needed to
diagnose why any particular title missed the pre-browser check.

The adapter supports [Gowitness 3.2.2](https://github.com/sensepost/gowitness/releases/tag/3.2.2) and checks `gowitness version` before capture. Chrome or Chromium must already be installed or supplied through `chrome_path`. Recognized browser commands include Chromium, Google Chrome, and `google-chrome-unstable`; the explicit browser path is always passed to Gowitness. The adapter does not request a browser download or reuse a logged-in browser profile.

The [pinned CLI](https://github.com/sensepost/gowitness/blob/3.2.2/cmd/scan.go) is invoked with `scan file`, PNG filesystem output, `--write-jsonl`, an explicit JSONL destination, bounded threads, scan-error logging, and HTML/network-body collection disabled. A global subprocess deadline and cooperative cancellation bound the batch. Input contains `http://domain:80` and `https://domain:443`. Explicit ports matter because the [file reader](https://github.com/sensepost/gowitness/blob/3.2.2/pkg/readers/file.go) otherwise expands the default port list even when a scheme was supplied.

The adapter joins exact requested URLs to the [JSONL result model](https://github.com/sensepost/gowitness/blob/3.2.2/pkg/models/models.go): `url`, `probed_at`, `response_code`, `title`, `file_name`, `failed`, `failed_reason`, and `is_pdf`. Redirect destinations do not replace the requested identity. The [driver](https://github.com/sensepost/gowitness/blob/3.2.2/pkg/runner/drivers/chromedp.go) supplies the screenshot basename; filenames are never guessed from domains.

Each attempt receives `captured`, `failed`, `unavailable`, or `skipped` status, timestamp, and diagnostic fields. Skipped endpoints were checked without launching Gowitness; no responding endpoint means no browser process or version check is started. Accepted images must exist under that run's `screenshots/` directory, have PNG/JPEG signatures and matching extensions, and pass path and symlink checks. Missing/malformed metadata, duplicate URL records, filename collisions, and missing images remain explicit failures. Partial results survive ordinary tool failure or timeout. Old assets are never reused as a fresh capture. Screenshot failure does not change DNS observations or their baseline.

The default browser driver is `gorod`; `--capture-driver chromedp` remains an alternative. The pinned Gowitness binary and the default driver successfully captured three local fixture pages with the installed Chrome browser. Tests did not visit external domains. The offline demo uses those labeled fixture images.

Automatic pixel/perceptual image comparison and changed/unchanged/similar image
badges have been removed. The website changelog uses static text, title,
form/link and endpoint observations only. A periodic screenshot of unchanged
content does not enter a change-only report; it remains in inventory/history for
manual review. Full reports retain all eligible current-run captures.

Failed connection/TLS preflight checks never enter Gowitness. They are omitted
from website review cards in both report modes and summarized in a collapsed
**Website-check diagnostics** section instead, with separate no-response and
uncertain counts and up to 20 candidate-history links. Saved diagnostics remain
available in candidate history and the run's `preflight.json`. A previously
responding endpoint that stops responding is marked in those diagnostics.
DNS inventory is unaffected, and future scans check these endpoints again.
An HTTP response with incomplete text can still reach Gowitness; that differs
from a TLS/connection check that produced no HTTP response at all.

Before either URL enters Gowitness, the per-domain pair is checked for matching
complete fetched HTML. The decoded body bytes are hashed incrementally to EOF
within the existing timeout and byte cap; truncated/missing/unreadable bodies
cannot match. Content type/charset, title, final status and destination
host/path/query must also match. Otherwise eligible pairs share one browser
request, preferring HTTPS (or an observed changed protocol in change-only mode).
A deliberately skipped protocol does not force a new image on the next unchanged
scan solely for its missing image if the paired protocol has passed the existing
saved-image, route and refresh-age checks. DNS and other domains keep streaming
while each hostname waits for its own pair.

The text extraction cap (12,000 characters, plus link/form/depth limits) is
independent of the complete-body read. Reaching a text cap stops the parser,
while the response continues through the bounded body hash reader. A
`content_status: truncated` text excerpt can therefore have
`body_status: complete` and qualify for HTTP/HTTPS deduplication. A genuinely
truncated HTML response, byte-cap hit, timeout or read error still cannot match.
**Capture decision** and the live decision log record body-read status and why
the pair was merged, unavailable, or different (body bytes, endpoint, title or
content type). Similar-looking screenshots alone do not establish identical HTML.

The report combines a matching pair into one card, explicitly naming the protocol
captured and retaining each protocol's change details. Both check records remain
saved. The duplicate row has `skip_reason: duplicate_body` and
`duplicate_body_of`; the selected row records `body_shared_with`. No image path
or successful capture is fabricated for the skipped protocol. If the selected
browser fails, its failure remains visible rather than claiming both protocols
were captured. No image files or old reports are deleted. Equality of static HTML
does not prove equal rendered pixels or external/JavaScript content; neither
pixel comparison nor text-only similarity drives this optimization.

### Shared page groups across domains

The report's **All pages / Shared bodies / Other pages** tabs group its selected
entries within one client's scan. Exact complete HTML matches share a card.
New scans also compute a separate `self-host-html-v1` template fingerprint:
only whole occurrences of the scanned hostname and its `www` form are replaced
with a placeholder. For example, a Dovendi page naming `fqq.nl` can group with
the otherwise identical page naming another scanned domain. Other text,
provider names, prices, forms, scripts, styling and unrelated hostnames remain
meaningful. This is not broad fuzzy matching or a parking-provider verdict.

Template fingerprints require complete bounded HTML with strict character
decoding. They use at most the existing 64 KiB/512 KiB body buffer and timeout;
partial or unreadable bodies remain separate. The buffer is not saved or sent
to AI. Older records without template metadata can still group exact complete
bodies; domain-normalized groups require a new scan after rebuilding.

Cards identify exact versus domain-normalized matches and show one actual
example image. **View all matching domains** opens a paginated member page with
the real names, protocols, titles, changes, individual images and history links.
Only entries allowed by the run's full/change-only policy and exclusions enter
these groups. Groups never mix clients or scan histories. Missing body data is
not an empty-body match. Rendered-title differences are shown when present.

Cross-domain grouping is a report view, not screenshot reuse or suppression:
hostname-dependent JavaScript and external content can render differently even
with identical HTML. Each domain keeps its own capture and DNS/change evidence.
The existing same-domain HTTP/HTTPS capture deduplication still uses exact
bodies, never the domain-normalized template fingerprint. No image comparison,
AI behavior or GoDaddy exclusion logic is changed by grouping.

### Similar main content and protocol fallback

A third, **Similar content** label can connect pages whose complete HTML differs
but whose normalized main text, static title and full link/form collections
match. A separate bounded parser ignores recognized consent containers (for
example Cookiebot, OneTrust, CookieYes, Complianz and common consent-banner IDs)
without dismissing cookies or changing the saved page text. Scripts, styling
and image/logo differences do not enter this report-only content signature.
Generic words such as “cookie” do not trigger removal of arbitrary content.

The grouping signature masks whole tokens for the scanned hostname and its
parent names down to two labels, allowing registry welcome pages naming
`nl.gp` versus `nl.kg` to be considered alike. This is a display normalization,
not an ownership/public-suffix assertion. Own HTTP/HTTPS URL schemes and default
ports normalize together; unrelated destinations, link paths/queries, form
purposes, prices, case and other main text remain meaningful. Whitespace is
collapsed. At least 120 normalized characters and 15 words are required.
Truncated, sparse, unreadable, unclosed hidden/consent blocks and exhausted
budgets do not produce a content match. Original observations are unchanged.

These are candidate content groups, not proof of identical HTML, screenshots,
provider identity or safety. Exact and domain-template matches retain their
stronger labels. Every member's original image and details stay available.
Similarity fields are collected on new scans only and never drive Gowitness
selection, title exclusions, AI selection or change detection. If the optional
parser runs out of its remaining budget, already completed raw-body evidence
is retained rather than forcing an extra browser capture.

When unmatched HTTP and HTTPS entries for one domain both remain in the report,
they appear inside one **HTTP / HTTPS views** card, with independently labelled
images, titles, capture outcomes and comparisons. This fallback makes no body
match claim, does not resurrect excluded/unchanged entries, and also works on
older saved reports after the application rebuild.

The same layout also pairs an HTTP-only shared group with an HTTPS-only shared
group when their **entire domain lists match exactly**. Each side keeps its own
example screenshot, titles, capture decisions and content-match label. The
combined card links to all observations and to each original protocol group;
existing links to those groups remain valid. Pairing compares the full lists,
not just the domain preview, counts or example domain. A partial overlap, or a
group that already contains both protocols, stays separate. This is a display
pairing, not an additional content match or a reason to skip either capture.

Distinct HTTP/HTTPS bodies have separate screenshots. Candidate detail pages can
show earlier/current screenshots side by side, selected from saved history
without decoding or comparing their pixels. Historical visual-comparison metadata
is retained on disk but does not drive report selection or gallery labels.
The optional AI handoff is text-only and deduplicates equivalent same-host
protocol text histories. No image bytes or image URLs enter AI review.
Use the [standalone runner](../standalone/README.md) and its local HTML/JSON report
to inspect text transfer volume before enabling n8n.

The gallery renders image frames only for saved screenshots. A single successful protocol uses the card's available width; the other protocol appears as a compact status row. With no image, the domain remains a compact DNS entry with check details. An earlier successful image can remain visible with a clear previous-capture label when a newer attempt fails or is skipped.

Capture opens untrusted pages and can follow redirects, execute JavaScript, and request third-party resources. Gowitness's Chromium driver itself ignores certificate errors and disables Chrome's sandbox. Run it with the container's limited permissions and an appropriate network boundary; checking the initial domain's public IP alone does not constrain later browser requests. This adapter does not provide a complete browser/network sandbox. No external sites are visited by the fixture tests.
