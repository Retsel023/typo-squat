# n8n Cloud text review

Import [`n8n-text-review.json`](../workflows/n8n-text-review.json). It starts or
resumes a scanner run over HTTPS, polls for completion, and optionally reviews
new/changed **text** with **gpt-4o-mini** using n8n's native OpenAI node.
The export is inactive, its schedule is disabled, and `ai_enabled=false`.
The older `n8n-visual-review.json` filename now contains the same text-only
workflow for compatibility. Replace old imported image workflows; the scanner
rejects their `include_images=1` requests, and no longer returns image URLs from
its automation manifest. Screenshots remain in the manual review UI.

The scanner and Linux tools run on your own server, in Docker or natively.
n8n Cloud communicates through HTTP; it does not run the scanner container.
The [standalone scanner](../standalone/README.md) works without n8n or AI.
Native per-project schedules can independently enumerate monthly and check
cached inventory weekly. Avoid enabling both native and n8n scheduling unless
you intend separate scan attempts.

## Connect

1. Set `TYPO_MONITOR_API_TOKEN` to a private value of at least 32 characters on
   the scanner. Expose its authenticated `/api/` routes over HTTPS through your
   reverse proxy. n8n Cloud cannot reach your laptop's `127.0.0.1` or Docker names.
2. Import the JSON. In **Configure monitor**, set `api_base_url` and `project_id`.
   Set `existing_run_id` to review a completed run without starting another scan.
3. Create n8n **HTTP Header Auth** with `Authorization: Bearer YOUR_TOKEN` and
   select it on **Start scan**, **Get run status**, **Get changed text manifest**,
   **Fetch one text pair**, and **Save AI assessment**. No credential is embedded.
4. Leave `ai_enabled=false` initially. Only status and one metadata page enter
   n8n; no text bodies or model requests are fetched. Use the scanner's local
   **AI handoff preview** or standalone `handoff-preview` to inspect volume.
5. When ready, select your existing OpenAI credential in **Review with
   gpt-4o-mini**, set `ai_enabled=true`, and start with `review_limit=1`.

Use a current n8n release with native OpenAI node v2.3 and the text **response**
operation. The export uses two text messages, no binary input, no tools,
structured JSON output, an 800-token output cap and `store=false`. It keeps
exactly `gpt-4o-mini`; access errors do not substitute another model.
The suggested [system prompt](AI_TEXT_PROMPT.md) is embedded in **Configure
monitor → review_prompt**; editing the Markdown alone does not update an import.
Evidence is a separate user message. The model is told to treat page instructions
as untrusted evidence and to avoid unsupported visual/ownership claims.
See [OpenAI's model documentation](https://developers.openai.com/api/docs/models/gpt-4o-mini),
[structured output guide](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses),
and [n8n's text operation source](https://github.com/n8n-io/n8n/blob/master/packages/@n8n/nodes-langchain/nodes/vendors/OpenAi/v2/actions/text/response.operation.ts).

## What is compared and transferred

By default every scan repeats DNS and bounded HTTP/HTTPS checks. Static readable
HTML text is normalized locally and fingerprinted along with link destinations
and form/field purposes. Title and endpoint differences are tracked separately.
No scripts or styles execute, hidden input values are omitted, and no digits,
dates or contact details are stripped from readable text. Changing those details
can therefore trigger a review. Changing URLs/query strings can also trigger one.
This is a static HTML heuristic, not the rendered page: visual or JavaScript-only
changes may require periodic/full browser captures for human review.

A routine change-only scan skips Gowitness only when content, title, endpoint,
route and a saved successful screenshot baseline match and are not due for
refresh. A failed intervening browser attempt does not invalidate an older
matching successful image. Incomplete, oversized, unreadable, non-HTML, error or sparse dynamic
responses remain eligible for browser capture. They do **not** enter the AI text
queue because a complete useful comparison cannot be established.
Older scans without text need a fresh baseline. Title-only mode remains available
as a lighter project setting, but supplies no text AI queue.

The AI selector admits complete new/changed text even if its manual screenshot
failed. It excludes owned source domains, unchanged/uncertain text, explicit
exclusions, likely parking pages and matching saved text reviews. Equivalent
HTTP/HTTPS evidence is deduplicated only within the same hostname, with matching
current and previous content/title histories; different pages remain separate.
No cross-domain deduplication hides distinct domains.

Full capture mode respects global/project title exclusions too. Complete HTML
titles can exclude on any HTTP status. Gowitness titles are checked again after
capture; browser-only matches stay out of the AI queue and reports, while their
already-captured files remain in local history. A browser-only title cannot
prevent that first browser visit. Rules are the saved snapshot from queue time.

With AI enabled, one selected pair at a time includes:

- Up to 8,000 current text characters, title and sampled form/link details.
- Up to 2,000 previous text characters and a compact diff of up to 2,600 characters.
- Up to one owned-site reference from the same run, capped at 2,000 text characters.
- Timestamps, extraction status/version, hashes, URLs and explicit excerpt flags.

Link/form samples contain at most eight entries of 256 characters per category.
Hashes cover the full bounded extraction, while excerpts/samples sent to AI can
omit details. The prompt requires uncertainty when evidence is incomplete.
No screenshot bytes, image URLs, raw DNS inventory, proxy credentials, dataset
upload or training job is part of the request. Screenshots serve human review.

## Pages, polling and storage

`review_limit` defaults to five, accepts 1–25, and bounds model calls per execution.
The loop processes one pair at a time. Pages never continue automatically:
reuse `existing_run_id` and set `review_offset=next_offset` when `has_more` is true,
even if that page contained only already reviewed items. Requests use
`include_reviewed=1` so page offsets remain stable while callbacks save reviews.
Model calls and scan creation have no automatic retries. Failed callbacks may
require a repeated model request on a later manual execution.

Status polling defaults to 30 seconds with a 1,800-second deadline. Failed or
cancelled scans stop explicitly. A polling deadline or stopped n8n execution does
not stop the independent scanner; resume using its run UUID. Stop/disable native
scanner schedules separately in the UI when needed.

Output validation rejects refusals, incomplete responses, unexpected models/tools,
invalid JSON fields and change claims without a prior text baseline. Valid AI
assessments are saved separately from DNS findings, bound to the exact run,
hostname, protocol and text fingerprint. Risk/confidence are model opinions for
human triage, not authoritative phishing detection. No notifications, takedowns,
exclusions or other actions are triggered.

n8n can retain node outputs in memory. Keep batches small and inspect your Cloud
execution-data policy; the export disables saved successful, failed and manual
execution data where settings permit. `store=false` requests no retrievable
OpenAI response storage; it does not promise zero provider retention.

## API contract

All routes require the configured scanner Bearer token.

| Request | Result |
| --- | --- |
| `POST /api/scans` with `{"project_id":"UUID"}` | Queues a run. Optional `discovery_mode: "cached"` or `"enumerate"`, and `capture_mode: "changes"` or `"full"`, override project defaults independently. |
| `GET /api/runs/UUID` | Status and counts. Only completed/partial runs offer text review. |
| `GET /api/runs/UUID/text-review?limit=5&offset=0&include_reviewed=1` | Metadata list, summary, total and next_offset; no page bodies or images. |
| `GET /api/runs/UUID/text-review?include_text=1&domain=example.com&scheme=https&limit=1&include_reviewed=1` | One bounded text evidence pair. Explicit hostname/protocol required. |
| `POST /api/runs/UUID/text-reviews` | Saves `{domain,scheme,content_sha256,provider,model,summary,risk,changed,confidence}` if the fingerprint matches complete saved text. |

`/review` and `/reviews` remain aliases for the text contract; image transfer is
rejected. Importing this workflow and selecting credentials is still required.
This update was reviewed in source only: no tests, scans, Docker build, n8n
execution or live model request was run.
