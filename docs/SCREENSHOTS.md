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

HTTP/HTTPS screenshots are displayed independently. Candidate detail pages can
show earlier/current screenshots side by side, selected from saved history
without decoding or comparing their pixels. Historical visual-comparison metadata
is retained on disk but does not drive report selection or gallery labels.
The optional AI handoff is text-only and deduplicates equivalent same-host
protocol text histories. No image bytes or image URLs enter AI review.
Use the [standalone runner](../standalone/README.md) and its local HTML/JSON report
to inspect text transfer volume before enabling n8n.

The gallery renders image frames only for saved screenshots. A single successful protocol uses the card's available width; the other protocol appears as a compact status row. With no image, the domain remains a compact DNS entry with check details. An earlier successful image can remain visible with a clear previous-capture label when a newer attempt fails or is skipped.

Capture opens untrusted pages and can follow redirects, execute JavaScript, and request third-party resources. Gowitness's Chromium driver itself ignores certificate errors and disables Chrome's sandbox. Run it with the container's limited permissions and an appropriate network boundary; checking the initial domain's public IP alone does not constrain later browser requests. This adapter does not provide a complete browser/network sandbox. No external sites are visited by the fixture tests.
