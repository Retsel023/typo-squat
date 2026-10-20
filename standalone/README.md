# Standalone scanner with Docker

This folder runs the current application without n8n or local AI. Docker builds
from the shared [`monitor/Dockerfile`](../monitor/Dockerfile), including Python,
Amass **4.2.0**, MassDNS **1.1.0**, Subfinder, Assetfinder's pinned **v0.1.1**
prerelease CLI, Gowitness **3.2.2**, Chromium and the locked Python
dependencies. You need Docker Engine and the Compose plugin on the host; you do
not need to install Python, Go, Chromium or scanning tools there. Keep this folder beside `monitor/`
in the repository: it deliberately shares that source instead of copying it.

The standalone profile has its own persistent named volume for SQLite, scan
artifacts, full screenshots and reports under `/data`. It runs as UID/GID 10001,
binds its web interface to your host's loopback address, and disables the optional
automation API. It does not upload evidence to n8n or OpenAI. Real scans and
screenshots use normal DNS and website connections; the simulated demo and local
handoff report make no external requests.

## Start the application

From the repository root:

```sh
cd standalone
export TYPO_STANDALONE_PORT=5057
docker compose up --build -d
```

Open <http://127.0.0.1:5057>. This example uses 5057 so an existing native
profile can keep using 5055. Create a project in the UI using your root domains,
one per line, and start scans from its project page. The server offers manual
scans by default. Use **Stop scan** to cancel a running or queued client scan;
previously accepted results stay available and unfinished work is not published.
To inspect startup or stop the server:

```sh
docker compose logs --tail=100 monitor
docker compose stop monitor
```

The Compose default remains 5055; `TYPO_STANDALONE_PORT` changes only the host
port. Keep the variable exported for later Compose startup/rebuild commands. The
container still serves port 5000, and its healthcheck uses that internal port.
After pulling code updates, rebuild the image to run the new application:

```sh
TYPO_STANDALONE_PORT=5057 docker compose up --build -d
docker compose logs -f --tail=100 monitor
```

The native Python launcher stores clients and history in `standalone/data/`.
Docker uses its named volume mounted at `/data`, so native clients do not
automatically appear in the Docker profile. Changing ports does not copy or
switch either data store. You can inspect native 5055 and Docker 5057 separately;
an empty Docker dashboard does not mean the native data was lost.

`docker compose down` retains the named data volume. `docker compose down -v`
deletes that profile's saved data. The main `monitor/` Compose profile uses a
separate volume.

Each client's **Scan schedules** panel has independent intervals for **Full
enumeration** and **Saved inventory**. Set full enumeration to **720 hours**
(every 30 days) and saved inventory to **168 hours** (weekly), for example. Both
check DNS again; saved inventory skips subdomain discovery and typo generation.
Each accepts 0 (off) or 1–8760 hours. These are elapsed-hour intervals, not calendar
month dates. Saved-inventory scheduling waits until the first accepted inventory.

When both are due, one full scan covers both. Starting a full scan advances both
intervals; starting a saved-inventory scan advances only that interval. Weekly
checks therefore do not postpone monthly enumeration. Existing single schedules
keep working until you save the new form. **Turn both off** disables this client's
automatic scans, including the server fallback. Due times persist in the volume;
the server must stay online. **Stop scan** leaves future schedules enabled.

Choose **Use saved inventory** beside **Start scan** for a manual scan that skips
Amass, Subfinder, Assetfinder and generation but repeats DNS for every saved
candidate, including negative/uncertain names. **Default for manual scans** saves
the initial selection; each automatic cadence chooses its own mode. Every queued
scan retains its mode and concurrency settings.

Use **Manage project** on the client's page to rename or delete it. Finished scans
have **Delete report** links in history and run details. Each deletion opens a
confirmation page. Report deletion removes that run's observations, screenshots,
reviews and logs while retaining current project inventory/DNS state, generation
cache and minimal schedule/baseline bookkeeping. Project deletion removes all of
that client's managed data and schedules. Stop any active scan and wait for its
worker to finish first. Previously exported files elsewhere are separate. No data
is deleted merely by rebuilding/upgrading.

The supplied Compose mount explicitly allows execution from `/tmp`, needed for
Gowitness/Rod's extracted Leakless helper. If an older container logged
`fork/exec /tmp/leakless-...: permission denied`, recreate it with the updated
Compose file. The unprivileged user, read-only image, dropped capabilities and
`no-new-privileges` setting remain in place. See [mount options](https://docs.docker.com/engine/storage/tmpfs/#options-for---tmpfs).

The client's **Proxy routes** panel has independent SOCKS5 switches for discovery,
DNS lookups, and website checks + Gowitness. For a custom proxy, enter a reachable
`socks5h://host:port` or `socks5h://user:password@host:port` for each stage, then
save. The same URL can be reused. Empty URL fields retain existing settings;
credentials are not displayed in reports. All switches initially stay off and
saving does not test/connect to the proxy. Scans queued afterward, including
scheduled scans, keep a snapshot of these settings.

DNS needs a SOCKS5 server supporting **UDP ASSOCIATE**; a typical SSH SOCKS tunnel
is TCP-only. Website checks and Chromium use the same selected route. Discovery
proxying uses Subfinder + Assetfinder and **skips Amass 4.2**, whose internal DNS
traffic cannot be covered by the provider proxy. This limitation is shown next
to the switch and in source health. DNS parking checks use the DNS proxy too.
There is no automatic direct retry on proxy failure. A changed DNS proxy route
starts a fresh DNS baseline on the first accepted informative scan while retaining
old reports and inventory. IP rotation depends on your provider, and existing
concurrency limits still apply. See [full proxy behavior](../monitor/README.md#per-stage-socks5-proxies).

Rebuild/recreate after this update to install PySocks in the image. Keep your
existing Compose port/resolver/environment settings; the proxy addresses themselves
are configured in the UI. A proxy must be reachable from the container, so a
`localhost` URL refers to that container rather than your host's local proxy.

For provider-free routing, the optional **Tor** profile supplies a preset address
for discovery and website capture. Choose **Use Tor · preset address** in those
stages and leave the custom URL fields empty. First start the Tor container and
wait for it to become healthy; selecting Tor in the UI never starts Docker.
DNS still needs a separate UDP-capable proxy if you want to proxy that stage.
The Tor port is not published on your host, its client state has a separate
volume, and it does not automatically restart with Docker. See the
[Tor setup guide](../docs/TOR.md) for the complete startup command preserving
port 5057, candidate limits and DNS settings, plus logs and shutdown commands.

Choose **DNS concurrency** when creating a client, or save it on the client's page
before starting a scan. Use 20 for up to 20 simultaneous DNS questions with MassDNS; the supported
range is 1–128. A blank setting follows the server default of 24. This setting
also controls subsequent DNS parking checks. HTTP/text checks and browser
captures have separate worker limits. Each queued scan keeps its chosen count, so editing a
client affects scans queued afterward. The run page shows the count used.

To change the Docker server default for clients that inherit it:

```sh
TYPO_DNS_WORKERS=20 TYPO_STANDALONE_PORT=5057 docker compose up --build -d
```

Saved client overrides still take precedence. MassDNS is the default lookup
backend (`TYPO_DNS_BACKEND=massdns`); select `TYPO_DNS_BACKEND=dnspython` for the
Python implementation. MassDNS performs bulk A, AAAA and CNAME queries with
bounded concurrency. Missing replies and failed queries remain uncertain, not
absent. All inventory names are queried again on every run; generation caching
never substitutes for fresh DNS. The Python option uses the same saved setting
as its domain-worker count. See [DNS backend details](../docs/DNS.md).

The rebuilt MassDNS binary is **1.1.0+typowatch2**, with resolver ownership fixes
for the pinned upstream release plus the existing strict JSON/wire validation.
Older binaries fail the capability check before a batch starts. A process
abort with no trustworthy DNS results is reported as a failed scan and keeps
the accepted inventory, rather than appearing as completed with gaps.

Optional `TYPO_DNS_RESOLVERS="1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4"` supplies a
pool; `TYPO_DNS_RESOLVER_MODE=balanced` consistently spreads hostnames across
it. Default mode is `ordered` failover. Changing that DNS view requires a new
baseline after informative results have been accepted. Concurrency controls
outstanding requests, not QPS. See [pool configuration](../docs/DNS.md#settings-and-output).

The default `TYPO_MAX_CANDIDATES=250000` guard stops a run before candidate DNS
checks if typo generation plus retained inventory exceeds that many unique
hostnames. This count includes unverified candidates, not just domains that
resolve. Inspect `discovery-hostnames.txt` in run output for filtered discovery
names, and `generation.json` for the expansion counts. To allow up to a million
candidates after reviewing that expansion, recreate with:

```sh
TYPO_MAX_CANDIDATES=1000000 TYPO_STANDALONE_PORT=5057 docker compose up --build -d --force-recreate monitor
```

The named data volume is retained. Keep the chosen value in this folder's
`.env` file for later Compose invocations. Exceeding the limit preserves the
previous accepted inventory and DNS baseline.

Discovery defaults to `TYPO_DISCOVERY_ENGINE=combined`: Amass **4.2.0**,
Subfinder with `-all`, and Assetfinder run concurrently. Their normalized,
in-scope names are deduplicated before generation, with per-tool health and
hostname provenance retained in `discovery.json`. Partial results remain usable
when another tool fails or times out. Assetfinder does not expose individual
upstream provider failures, so its process success is not a provider health check.
Amass's compatibility pin uses a self-contained enumeration command; v5's
separate engine lifecycle needs a different integration. Select `amass`,
`subfinder` or `assetfinder` to run just one tool; single-engine selections never
silently switch to another engine. `TYPO_DISCOVERY_TIMEOUT` sets each tool's
per-root limit in seconds (default 600). For example:

```sh
TYPO_DISCOVERY_ENGINE=subfinder TYPO_DISCOVERY_TIMEOUT=600 TYPO_STANDALONE_PORT=5057 docker compose up --build -d
```

The selected tool's failure or timeout is visible in source health. Saved seeds
and candidates are retained, and every saved candidate is still checked by DNS.
Existing scan history continues to show the discovery engine used at the time.
See the [discovery guide](../docs/DISCOVERY.md) for supported tool versions and
native options.

Before opening Chromium, each resolving domain receives lightweight HTTP and
HTTPS checks on ports 80 and 443. Only responding endpoints are passed to
Gowitness; redirects and HTTP error responses still qualify. The check uses the
run's DNS worker limit and a 3-second timeout (`--web-timeout` in the native CLI).
A timeout remains uncertain. All endpoints are checked again on later scans.
DNS-only domains stay visible, with compact protocol status instead of empty
screenshot panels. A previous successful image is labelled as an older capture.
Detailed checks are retained in `/data/runs/RUN_UUID/preflight.json`.

To avoid browser captures for known unwanted page types across all projects,
use **Global exclusions** in the sidebar. Existing and new projects inherit
this shared list. Add client-specific phrases under each project's
**Screenshot title exclusions**. Enabled lists are combined with duplicates
removed; a project's switch controls only its additional phrases. Each list
allows up to 50 phrases of 120 characters and has its own enable switch.
Global settings persist in the data volume alongside project settings.

Enable the option, enter specific title phrases such as `GoDaddy` or a station
name (one per line), and save before
starting a scan. Matching ignores case and checks HTTP and HTTPS independently.
Exclusion rules are off by default. Website checks reuse the GET, reading
up to 64 KiB of HTML in title-only mode or 512 KiB in default text mode, following at most three redirects within
the probe's timeout budget. They use the same website proxy as Gowitness.

Complete HTML titles are matched as case-insensitive literal substrings on
any HTTP status, including errors. `godaddy` therefore matches titles containing
`GoDaddy`. Full capture/report does not bypass exclusions. Original roots and
discovered source subdomains still bypass them so reference captures remain
available.

HTML and browser requests use the same user-agent, and bounded gzip/deflate
HTML decoding is supported. Missing or unreadable HTML titles still reach the
browser. A JavaScript/browser title can differ from the original HTML title.
The returned Gowitness title is checked again: matches are excluded from both
report modes, the normal gallery and AI, but the already-captured file remains
in history. Seeing a first capture in the Gowitness log is therefore possible
when only the browser reveals the matching title. Counts distinguish skips
before Gowitness from exclusions after browser capture.

Title-filter decisions, matched phrases and global/project scope are saved with
the observations. DNS inventory remains intact and future scans check it again.
Changing rules affects newly queued manual/scheduled scans, not a scan already
running. Run details show its saved rule list. Title comparisons continue when
both exclusion lists are off.

Routine scans default to **Changes only**. Every run refreshes DNS and
HTTP/HTTPS checks; subdomain enumeration is independent. The project
**Screenshot and report policy** defaults to **Title + static structure**, with
**Titles only** available as a lighter option. Text mode reads up to 512 KiB of
static HTML and retains at most 12,000 readable characters. Complete HTML also
gets a versioned structure fingerprint: element order, selected layout attributes,
resource references, inline script/style code and form/link details. Visible prose,
prose labels, nonces and hidden input values do not contribute to that structure
fingerprint. Resource file contents and rendered layout are not fetched/compared.

A wording-only change with the same complete static structure, title, endpoint
and website route goes to a collapsed **Text-only updates** log. With a valid saved
image baseline, changes-only scans skip Gowitness **before the browser queue**;
this is not just report filtering. The text diff and its source report remain
available. Later unchanged scans keep using that image baseline despite its older
wording, instead of recapturing the page on the following run. New pages and
changes to titles, structure, resources or form/link details remain browser-eligible.
A structure change takes priority even when the readable text also changed.

Full capture mode, configured periodic refreshes, missing/mismatched image
baselines and incomplete/unreadable/sparse checks can still request screenshots.
A text-only log row records the actual browser decision. Prior reports have no
structure fingerprint, so fresh comparable observations are needed before a text
change can be treated as wording-only. The old text hash remains compatible;
existing reports and screenshots are preserved. Static markup cannot establish
that a remotely updated CSS/image file or JavaScript-rendered layout is unchanged.
Screenshots remain for manual visual review.

Each report entry has **Capture decision**, explaining full mode, periodic
refresh, an uncertain check, a missing/mismatched image baseline or a changed
proxy route. Older scans without decision metadata say it was not recorded.
Automatic image change detection and similarity badges are removed. Even
historical image-comparison metadata cannot add entries to change-only reports.
Periodic screenshots of unchanged text stay in inventory/history for human review,
and full reports still show all eligible captures. HTTP/HTTPS results stay
separate unless their complete fetched HTML matches within the same domain;
matching pairs share one browser capture. AI behavior is unchanged.

The **Website changelog** shows new/changed observations, before/after titles,
expandable text diffs and this run's screenshots. It does not repeat old images.
The inventory and older reports retain the complete history. DNS changes remain
separate; changes do not prove a purchase or maliciousness.

Each new scan can use the latest reliable website observations across accepted
history for that client, domain and protocol. Titles, complete page text and
connection/HTTP results are selected separately, so an incomplete run or a
title-only scan cannot erase an older complete text check. **Capture decision**
links to each source scan and timestamp. `A → failed read → A` can stay
unchanged; `A → B → A` still reports the return from B to A. Only comparable
text extraction versions are used. Earlier reports are not rewritten, and
explicitly deleted report evidence is no longer available to comparisons.

The scan-history **Website changes** column counts new/changed website
observations; DNS totals appear underneath as side notes. DNS state and discovery
inventory already accumulate across runs. Changed IP answer sets remain in a
collapsed **DNS side notes** section. HTTP destination/status, TLS and connection
changes have their own collapsed network notes and cannot by themselves add
a website-change card. Title/structure/form/link differences still count;
wording-only differences with complete matching structure evidence are logged separately. Older
network-only entries also stay out of changes-only cards; stored evidence and
full-report views are retained.

**Full capture / report** captures all eligible endpoints, respecting title
exclusions. The default periodic recapture age is 30 days (0 disables, up to 365).
Static text cannot reveal purely visual or JavaScript-only changes, so full or
periodic captures still help human review. Unchanged text stays out of the AI
queue even when a periodic/full screenshot changes.
Each enumeration/cached schedule independently selects changes/full; monthly
full enumeration/capture can accompany weekly cached changelogs. If both are due,
full capture wins when either requires it. Policy is snapshotted at queue time.
Native scans accept `scan --capture-mode changes` or `full`; the API accepts
`capture_mode` independently of `discovery_mode`.

Before Gowitness, both protocols are checked for each hostname. A complete-body
SHA-256 (decoded HTTP content bytes, without text normalization), matching
content type/charset, title, final status and destination host/path/query allow
one browser request for an otherwise eligible HTTP/HTTPS pair. HTTPS is preferred;
a change-only report prefers a protocol with an observed change. Both check
records are saved, and the report combines them into one card identifying the
protocol actually captured. No bodies are compared across different domains.

The fingerprint reuses the existing GET, byte limits and timeout, reading to EOF
within those limits. Missing, truncated, unreadable or different bodies do not
merge. Title-only mode retains its smaller 64 KiB limit; text mode uses 512 KiB.
The 12,000-character text limit and link/form/depth caps stop text extraction
without stopping the independent bounded body hash read. Truncated saved text
can still have a complete HTML body fingerprint. In **Capture decision** and
`capture-decisions.log`, body-read status is separate from text-read status;
HTTP/HTTPS comparisons record unavailable data or the differing comparison
fields when the URLs are kept separate. This does not infer body equality from
similar screenshots or compare a partial-body prefix as a complete response.
A skipped duplicate does not force an extra screenshot on the next unchanged
scan solely because it has no image, when its paired protocol still has a valid
unchanged image baseline. A failed selected capture stays a failure; the skipped
protocol does not claim a screenshot, and both endpoints are checked next run.
HTML equality is not a guarantee of identical JavaScript execution, external
assets or rendered pixels; no image comparison is performed.

Reports also have **All pages / Shared bodies / Other pages** tabs. Within each
client's scan, matching complete HTML appears once with a representative image
and a link to all matching domains (100 entries per member page). New scans
compute a separate template fingerprint that replaces only the scanned
hostname, with or without `www`, with a placeholder. This groups otherwise
identical sale pages whose domain name differs, while preserving other content
and recording the real domains/titles unchanged. Exact and domain-normalized
matches are labelled separately. Incomplete/unreadable bodies stay individual;
older reports without template fingerprints can group only exact matches.

The report's existing changes/full mode and exclusions are applied before
grouping. Individual images, website change details, DNS state and history stay
available. Cross-domain grouping does not skip browser captures or infer a site
is harmless or owned by a particular provider. Same-domain HTTP/HTTPS capture
suppression still requires exact complete bodies. AI and title exclusions are
unchanged. Rebuild and start a new scan to collect hostname-normalized template
metadata; this does not rewrite historical observations.

New scans also collect **Similar content** grouping signatures. These compare
complete main text, static titles and full link/form collections after excluding
recognized consent popup containers and normalizing current-host/parent names
and own HTTP/HTTPS URL schemes. Scripts, styling and images do not enter this
content signature, so cookie UI or registry logo variations need not produce
separate report cards. Other destinations, form purposes and main content still
matter. Short generic text, truncated reads, malformed hidden blocks or a
spent time budget stay unmatched. Original text/change evidence stays intact;
this is a report aid, not screenshot equality, provider attribution or a reason
to skip browser captures. Unknown consent markup can still stay separate.

If no content match is established, the remaining HTTP and HTTPS entries for a
domain share one **HTTP / HTTPS views** card, with both images and their own
results. This fallback works with older reports and does not revive observations
excluded by the scan's report mode or title rules. HTTP-only and HTTPS-only
shared groups also share one card if their complete domain lists match exactly,
with separate examples, content-match labels and links to each original group.
Partial overlaps stay separate. Similarity normalization requires a new scan;
screenshot scheduling, AI and DNS behavior are unchanged.

An untitled page can also join matching main text and link/form structure if
there is exactly one consistent nonempty title for that content in the report.
Conflicting titles or failed title reads do not use this fallback. It needs the
extra main-content fingerprint collected by new scans; title changes and
exclusions keep their existing behavior.

Cards and protocol panels without a current-run image are hidden. Their
observations move into a collapsed **Screenshot diagnostics** log below the
report, with errors and capture decisions, 100 entries per page. Groups with
images retain all member observations and domain lists; existing reports and
group links remain usable. History, capture scheduling and browser-skipped
diagnostics are unchanged.

See [text-only n8n review](../docs/N8N.md) and the [suggested AI prompt](../docs/AI_TEXT_PROMPT.md).

MassDNS can feed this work before its bulk DNS job finishes. A domain is offered
only after its A, AAAA and CNAME questions are complete and the positive result
is validated. Bounded HTTP/HTTPS checks pass responsive URLs to one Gowitness
process through standard input. A full handoff queue defers names until the
final DNS pass, so slow browsers do not block DNS or lose names. Final captures
must belong to domains that resolve in the completed DNS results; accepted
findings still publish together at the end. Stop scan discards unfinished work.
The dnspython alternative remains DNS-first. Live pipeline progress displays
separate DNS, web-check and capture counts.

## Browser performance

Open **Screenshot and report policy → Website and browser performance** to set
concurrent browser captures (1–32), per-page timeout (5–180 seconds), screenshot
wait (0–30 seconds), and independent HTTP/text concurrency (1–128). Blank values
inherit the server defaults shown next to the fields. New scans freeze effective
settings at queue time, including scheduled scans; settings are shown in run
headers and browser progress. Existing queued/running scans keep their values.

Defaults remain 4 browser captures, a 60-second page timeout, a 3-second screenshot
wait and 24 HTTP/text checks. Start with 8 browser captures and a 1-second wait if
your hardware allows; shorter waits/timeouts can miss late content or slow pages.
See [performance settings and build commands](../docs/PERFORMANCE.md).

## Follow an actual scan

```sh
docker compose logs -f --tail=100 monitor
```

Logs include the run UUID and transitions through discovery, generation/reuse,
DNS, parking and screenshots. DNS progress reports checked,
resolved, negative and uncertain counts. The scan details page shows live stage
counts and an expandable **Live output** panel with activity and actual tool
output. It updates every four seconds while the panel is open, preserving your
reading position. Counts describe the current stage; accepted findings appear
after the run completes.

The page displays escaped plain text with terminal controls removed. Only
explicit tool log/output names are read, capped at eight recent sources,
12 KiB each and 64 KiB total. Output may arrive in batches because tools buffer
their writes. Python DNS checks show activity and counters instead of external
command output. Progress snapshots and the latest 200 activity messages are
saved under `/data/progress/`, separately from accepted findings. Old runs can
show retained tool logs, but detailed counters require a scan using this
version. Rebuild after the current scan finishes, since recreating the service
interrupts the worker.

Tool-specific output is stored under `/data/runs/RUN_UUID/`. Once screenshot
capture has started, inspect its log without installing host tools:

```sh
docker compose exec monitor tail -n 50 /data/runs/RUN_UUID/gowitness.log
```

Generation attempts also retain `generator.log`. Combined discovery places
each tool's files under `discovery/amass/`, `discovery/subfinder/` or
`discovery/assetfinder/` within the run folder. Amass retains per-root
`amass-N.txt` typed asset/relationship output, `amass-N.stdout.log`,
`amass-N.stderr.log`, `amass-N.engine.log` and `amass-db-N/` working data. Those
discovery relationships are not current DNS evidence; DNS is checked afresh.
Subfinder and Assetfinder retain their own output and stderr. Single-engine
runs keep their files directly in the run folder. A reused generation
cache does not launch AIL or create a new AIL log. For native runs, the same
application stage messages appear in the terminal and tool logs live under
`standalone/data/runs/RUN_UUID/`.

## Inspect the current progress with local examples

Build once and seed the demo while the server is stopped:

```sh
docker compose build
docker compose stop monitor
docker compose run --rm monitor doctor
docker compose run --rm monitor demo --report-output /data/reports/demo
docker compose up -d
```

Open the UI and select the **Simulated demo** project. Its gallery includes
labelled reference and imitation screenshots, before/after changes, HTTP/HTTPS
duplicate collapse, parking and failed-capture examples. These are simulated
observations, not findings about real domains. The demo also writes
`/data/reports/demo.html` and `demo.json`, showing the first five pairs that would
qualify for optional AI text review and their measured text size. Repeating `demo`
creates another simulated project.

The server and commands such as `demo`, `doctor` and `scan` use an exclusive
worker lock for the same data directory. Stop the server before running those
commands. Use the running UI for real scans. The read-only `handoff-preview`
report can run while the UI is open.

## Inspect a review batch without connecting n8n

Copy a project UUID from its UI URL, then run:

```sh
docker compose run --rm monitor handoff-preview --project PROJECT_UUID --limit 5 --output /data/reports/latest
mkdir -p reports
docker compose cp monitor:/data/reports/latest.html ./reports/latest.html
docker compose cp monitor:/data/reports/latest.json ./reports/latest.json
```

Open `reports/latest.html` in your browser. Reports remain in the named volume
until you copy them; no host bind mount or ownership adjustment is needed. To
copy the demo report, use the same `cp` commands with `demo` instead of `latest`.
The `cp` examples use the running server container to access the shared volume.

For an explicit completed run or another page:

```sh
docker compose run --rm monitor handoff-preview --run RUN_UUID --limit 5 --offset 5 --output /data/reports/next
```

The HTML/JSON preview reports selected/excluded text observations, transfer
characters and UTF-8 bytes for the exact bounded text evidence batch. No images
or text bodies are embedded in the preview, and no external requests are made.
Counts include JSON escaping and repeated references; prompts and transport
wrappers are extra. Bytes/characters do not estimate tokens or price.

New/changed complete text qualifies; unchanged/uncertain text, owned domains,
likely parking pages, title exclusions, equivalent same-host protocol histories
and saved text reviews are excluded. A pair can include current/previous text,
a compact diff and one owned reference. Older image-only runs have no text queue
until a fresh text baseline is collected. The offline image demo therefore does
not simulate live text extraction or AI review.

The [separate n8n workflow](../docs/N8N.md) starts with AI disabled. It uses the
native OpenAI text response node with gpt-4o-mini when enabled. No screenshot
bytes or image URLs enter the AI request; screenshots are for human review.
No local AI model is required.

## Optional native Python runner

If you prefer a host Python installation instead of Docker, from the repository
root on Linux:

```sh
python3 standalone/run.py setup
python3 standalone/run.py demo
python3 standalone/run.py serve --port 5055
```

The native runner uses separate `standalone/data/` and `standalone/reports/`
folders; these are distinct from Docker's named volume. It disables the optional
automation API even if a token exists in your shell. `setup` creates a local
virtual environment and installs the locked Python dependencies. It does not
install system packages or scanner binaries. For real native screenshots,
install Gowitness **3.2.2** and Chrome/Chromium. Install MassDNS **1.1.0**
for bulk lookups, or choose `--dns-backend dnspython`. Default combined discovery
needs Amass **4.2.0**, Subfinder and Assetfinder; each can instead be selected
alone with `--discovery-engine amass`, `subfinder` or `assetfinder`.
`--amass-path`, `--subfinder-path` and `--assetfinder-path` supply native binary
paths, `--amass-config` supplies optional provider-only v4 YAML configuration, and
`--discovery-timeout` changes the per-root seconds limit. Unsupported Amass
versions are rejected visibly. The
[application guide](../monitor/README.md) documents these tools.

```sh
python3 standalone/run.py doctor
python3 standalone/run.py scan --name "My project" --domains /path/to/domains.txt
python3 standalone/run.py projects
python3 standalone/run.py report --project PROJECT_UUID --limit 5
```

Stop the native server before `doctor`, `demo` or CLI scans. Use
`--project PROJECT_UUID` on subsequent `scan` commands to keep the same inventory
and baseline. Reports may run while the UI is open. Optional built-in scheduling
needs no n8n: `python3 standalone/run.py serve --port 5055 --interval-hours 24`.
Global options precede the command, for example:

```sh
python3 standalone/run.py --gowitness-path /path/to/gowitness --chrome-path /path/to/chromium serve --port 5055
```

The Docker configuration reuses the maintained image definition. The current
discovery and streaming changes have not been built or run here; build the updated image and check
`doctor` before relying on its discovery results.
