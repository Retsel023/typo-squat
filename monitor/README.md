# Typo Watch v3

Linux server monitoring with Docker as an isolated test/deployment environment.
Python owns orchestration, persistent state, DNS result validation and the web interface.
MassDNS performs bulk A, AAAA and CNAME lookups by default; dnspython is an
explicit alternative.
AIL supplies its `runAll` permutation algorithms. Discovery defaults to Amass,
Subfinder and Assetfinder running concurrently, followed by one normalized,
deduplicated union. Each engine can also be selected alone, or discovery disabled.

For a separate local profile and a preview of optional AI handoff volume, use
[`standalone/`](../standalone/README.md). It needs neither n8n nor an AI model.

## Run in Docker

```sh
docker compose up --build -d
docker compose logs -f monitor
```

Open <http://127.0.0.1:5000>. Create a project, enter one root domain per line, and
start its first scan. Scanning runs in a background worker; page requests return
immediately. Projects wait in a single worker queue to bound resource usage.
Only one run per project can be accepted at once. Use **Stop scan** to cancel a
running or queued scan. Stopping is cooperative: the run becomes `cancelled`
immediately and its adapters stop as they reach cancellation checks. The last
accepted inventory, DNS baseline, generation cache and screenshots remain intact;
unfinished work from the stopped run is not published.

The image uses slim Python, Amass **4.2.0**, MassDNS **1.1.0**, Subfinder,
Assetfinder's pinned **v0.1.1** prerelease CLI, Gowitness, Chromium, locked Python
dependencies, and an unprivileged user. It
does not run Kali upgrades, the old installers, cron, or shell command queues.
SQLite and per-run artifacts live in the `monitor-data` named volume at `/data`.
The application filesystem is read
only; writable scratch space is provided at `/tmp`. Both Compose profiles explicitly
allow execution there (`rw,exec,nosuid,nodev,mode=1777`) because Rod/Gowitness
extracts and launches its Leakless browser helper from that directory. A `noexec`
mount produces `fork/exec /tmp/leakless-...: permission denied` before screenshots
can start. Recreate the container with the updated Compose file to apply the mount;
no change to Chromium's driver or container user is needed.

Stop with `docker compose down`. Keep the named volume to keep history. Back up
the volume while the application is stopped; copy the entire data directory,
including any SQLite WAL/SHM files. `down -v` removes the volume and its history.

Compose binds to host loopback. For a remote server, use an SSH tunnel or an
authenticated HTTPS reverse proxy. The application has CSRF protection and
escaped output but does **not** provide GUI user accounts. The optional automation
API has separate Bearer-token authentication; expose only `/api/` for n8n Cloud
and keep the GUI behind your own access controls.

## Follow scan progress

```sh
docker compose logs -f --tail=100 monitor
```

The application logs each run UUID and its discovery, generation/cache reuse,
DNS, parking and screenshot stages. DNS progress includes
checked/resolved/negative/uncertain counts. Native runs print the same messages
to their terminal. The scan details page also shows the current stage and its
counts, with an expandable **Live output** panel for activity and actual tool
output. It polls every four seconds, including while the output is open, and
preserves your reading position. Counts describe the current stage rather than
an estimated completion time or overall percentage.

MassDNS scans use an overlapping DNS/web/capture pipeline. Its live progress
shows separate counts for those stages rather than changing the displayed
stage each time a worker reports. The dnspython alternative still completes DNS
before starting website checks.

Tool output is displayed as escaped plain text with terminal controls removed.
The page reads only explicit tool log/output names, up to eight recent sources,
12 KiB per source and 64 KiB in total. Tool buffering can delay new lines; Python
DNS checks produce their own activity and counters. Progress snapshots and the
latest 200 activity messages live under `/data/progress/`, separate from
accepted findings. Older runs can show retained tool logs, but new progress
counters are recorded only by this version. Accepted findings appear when a
scan finishes.

Detailed tool logs remain in `/data/runs/RUN_UUID/`, including `generator.log`
when generation was needed, `gowitness.log` when captures were attempted, and
per-root discovery output and stderr files. Earlier runs retain their original
Subfinder artifacts and source metadata. For example, after screenshot capture
starts:

```sh
docker compose exec monitor tail -n 50 /data/runs/RUN_UUID/gowitness.log
```

Combined discovery stores each engine's output under
`/data/runs/RUN_UUID/discovery/ENGINE/`, plus `discovery.json` with per-engine
health and the engines that reported each hostname. Amass attempts retain
`amass-N.txt` (typed asset/relationship output), separate stdout/stderr and
engine logs, and `amass-db-N/` working data per root. Subfinder and Assetfinder
retain `ENGINE-N.txt` and `ENGINE-N.stderr.log`. Single-engine runs keep their
files directly in the run folder. These discovery records do not replace fresh DNS.

After updating application source, use `docker compose up --build -d` to rebuild
and recreate the image while retaining its named volume. Let an active scan
finish first; recreating the service interrupts its worker. The separate
[standalone profile](../standalone/README.md) documents using host port 5057 next
to an existing native listener on 5055, and explains their separate data stores.

## Run in a virtual environment

Use Python 3.10 or newer (the Docker image uses 3.12):

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m typo_monitor doctor
.venv/bin/python -m typo_monitor serve
```

Python setup needs no root access. Default combined discovery needs Amass
**4.2.0**, Subfinder and Assetfinder separately on `PATH`; explicit binary paths
are accepted through `--amass-path`, `--subfinder-path` and `--assetfinder-path`.
Combined mode runs the three engines concurrently, enables Subfinder's `-all`
providers, and retains usable results when another tool fails. A missing or
failed engine is visible in source health. Provider credentials are optional
and not bundled; Assetfinder suppresses individual upstream provider errors, so
a successful process does not establish that every provider worked.
Select `--discovery-engine amass`, `subfinder` or `assetfinder` to run just that
tool; a single-engine selection never silently switches tools.
`--no-discovery` explicitly disables discovery while retaining known inventory.
Amass v5 uses a separate engine lifecycle and is not supported by this adapter;
an incompatible executable produces a visible version diagnostic. Supply an
optional provider-only v4 YAML config with `--amass-config PATH` or
`TYPO_AMASS_CONFIG`. Scope, database and scan-mode overrides are rejected.
See [discovery configuration](../docs/DISCOVERY.md) for the
pin rationale and command details.

Install Gowitness 3.2.2 and Chrome/Chromium for native capture, or specify their
paths explicitly:

```sh
python -m typo_monitor --gowitness-path /path/to/gowitness --chrome-path /path/to/chromium serve
```

Captures are enabled by default. `--no-screenshots` explicitly skips them while
DNS monitoring continues. `--capture-workers` defaults to 4, `--capture-timeout`
to a 900-second drain deadline after the streaming URL input closes (or the
whole capture invocation for the DNS-first path), and `--capture-driver` to `gorod`; `chromedp` is also
available. Missing binaries and individual HTTP/HTTPS failures are displayed.
Browser captures have a separately configurable per-page timeout (60 seconds by default).
The Docker image already includes the required capture tools.

See [browser performance controls](../docs/PERFORMANCE.md) for per-project
settings, Compose environment variables, and why this server cannot be scaled
by duplicating monitor containers on one shared data volume.

Before Gowitness, lightweight HTTP and HTTPS checks test each resolving domain
on ports 80 and 443. Only responding endpoints reach the browser. Any HTTP
status qualifies, including redirects, 403 and 404; timeouts remain uncertain.
Use `--web-timeout` to change the 3-second check timeout. HTTP/text and browser concurrency have their own project settings, independent
of DNS concurrency. Results are
saved in `preflight.json` and refreshed on every run. Domains without a responding
website remain in DNS inventory, with compact status rows instead of empty
screenshot frames. An older saved screenshot is explicitly labelled as previous.

The sidebar's **Global exclusions** page manages a shared title list for all
existing and future projects. Each project's **Screenshot title exclusions**
panel can add client-specific phrases. Both switches are off by default;
enabled lists are combined and case-insensitive duplicates removed. Switching
off project rules does not disable global rules. Each list allows up to 50
phrases of 120 characters. Global settings persist in the same database as your
projects, so they survive container recreation with the data volume retained.

Enable a list and save specific, case-insensitive literal phrases such as
`GoDaddy` or a particular station name, one per line. The existing GET preflight reads
at most 64 KiB of decoded HTML in title-only mode, stopping after the title or head. The default text mode reads up to 512 KiB for normalized content. It follows
at most three HTTP redirects within the probe's timeout budget and uses the
same configured website proxy. This adds a bounded body read and possibly
redirect requests; it does not launch curl or another browser.

A complete HTML title is matched case-insensitively as a literal substring on
**any HTTP status**, including errors. Full capture/report and change-only scans
respect the same exclusions. Enabled rules are snapshotted when a scan is
queued, so changing a list does not alter an already running scan.

The HTML check and Gowitness now use the same user-agent. Identity, gzip and
zlib-wrapped deflate HTML are read incrementally with limits on decoded bytes
and compressed input; unsupported or invalid encoding remains uncertain. The
existing timeout and redirect limits still apply. Missing/incomplete titles
remain browser-eligible. The static HTML title can differ from the rendered
browser title because of redirects, JavaScript, cookies or server responses.

After Gowitness returns successful page metadata, its title is checked against
the same saved rule list. A match is explicitly **excluded after browser title
check**, omitted from both full and change-only reports, hidden from the normal
gallery and excluded from AI. This does not retroactively prevent the first
capture: its file/status remain in capture history. Run counts distinguish
pre-browser skips from browser-title matches. Static filter metadata records
`disabled`, `original_reference`, `title_unavailable`, `no_match` or `matched`.
The rendered check records its own source, matching phrase and rule scope.

Owned roots and discovered source subdomains continue to bypass title exclusions
so original references remain available. HTTP/HTTPS are evaluated independently.

An excluded endpoint retains its DNS records, title, matched phrase, global or
project rule origin and check details. HTML decisions appear in `preflight.json`;
both HTML/browser decisions are saved in capture metadata. Run reports and the
AI handoff preview count exclusions separately; excluded
captures send no candidate text to n8n. Existing historical screenshots are retained.
Every later scan checks the title again, so this is not a permanent domain
blacklist. Rules are a capture preference, not a benign-site classification:
a malicious site can copy any title. Keep rules specific or leave the filter
off when you need complete visual evidence. Settings are snapshotted when a run
is queued and apply to both manual and scheduled scans. Each run displays its
saved rules from both scopes; later edits do not rewrite past reports or alter
queued/running scans. Title comparisons continue when both exclusion lists are off.

**Live output → capture-decisions.log** records the fetched title/filter and
reason for selecting or skipping each endpoint before Gowitness. While the
browser runs it also records its reported title and screenshot result, marked
as awaiting artifact validation. Final records distinguish verified saved images
from title exclusions applied after capture. `have-screenshot=true` in
`gowitness.log` means Gowitness reports taking an image; it does not mean that
the report included it. The new log is bounded recent telemetry (2 MiB, with
older entries trimmed); accepted check/capture history remains separate. It
does not change filtering or prevent a browser-only title's first capture.

### Change-only screenshots and reports

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

Connection/TLS checks without an HTTP response already skip Gowitness. Both
report modes keep these records out of website review cards and summarize them
in collapsed **Website-check diagnostics**, with counts and up to 20 links to
candidate history. The complete diagnostics remain saved; endpoints are checked
again on future scans. This changes report presentation, not DNS state or the
browser eligibility of responding pages with incomplete text.

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

With MassDNS, a domain enters this pipeline only after all its A, AAAA and
CNAME questions have completed and its positive result is validated. A bounded
queue offers names to concurrent HTTP/HTTPS checks while MassDNS keeps running;
if the queue fills, those names wait for the final DNS pass rather than blocking
DNS or being lost. Responsive URLs feed one Gowitness process through standard
input, so a complete URL list is not required before the browser starts.
Each protocol is checked independently. Final capture acceptance is restricted
to domains that resolve in the final DNS results. The application still commits
inventory and screenshots together at the end; stopped or failed work is not
published. The dnspython alternative retains the DNS-first path.

The Python orchestration avoids Bash, cron and external `flock` binaries.
Native Windows compatibility has not been tested; Linux is the target.

## What comparisons mean

* Roots and previously discovered seeds are retained. AIL generates only for new
  seeds or a changed generator fingerprint; later scans reuse their saved
  permutations. Candidates remain the union of previous inventory and newly
  generated output. Every saved candidate is still checked by DNS each scan.
* Every candidate receives explicit A, AAAA, and CNAME observations. TTL, record
  order, duplicates, hostname case, and trailing dots do not produce changes.
  Query owners remain distinct from CNAME targets.
* Timeouts, SERVFAIL, incomplete RRsets, contradictory answers, and unchecked
  candidates are uncertain. The last good records remain available. A partial
  positive response cannot remove an older IPv6 or alias record.
* Previously resolving domains need two consecutive explicit NXDOMAIN/no-answer
  checks to confirm absent DNS. Unknown, unchecked, and failed scans break that
  confirmation sequence. DNS absence does not establish unregistration.
* The first informative scan establishes a baseline. Later events are **newly
  observed**, **DNS records changed**, **DNS absence confirmed**, and **resolves
  again**. Discovery cannot establish registration dates.
* Project roots are immutable and DNS comparison settings are saved. Changed
  resolver settings are rejected after the baseline: keep the same explicit
  resolvers or create a new project to establish a separate baseline.
* Failed stages do not publish a baseline or replace accepted observations.
  Interrupted jobs are marked failed on restart. User-stopped jobs are marked
  cancelled and cannot replace accepted observations. Graceful shutdown cancels
  queued work and interrupts adapters before accepting observations.

Recursive DNS is an observation of one resolver view at one time. Geo DNS,
rotating answers, caches, and real changes can alter records even when a domain
remains active. Passive discovery cannot be exhaustive. Keep resolvers consistent
and review source health before interpreting changes. Missing status refers to
the queried records, not registration status.

## Configuration and automation

Global options go before the command:

```sh
python -m typo_monitor --data-dir /srv/typo-monitor --resolver 1.1.1.1 serve --interval-hours 24
python -m typo_monitor --data-dir ./data --no-discovery scan --name Example --domains domainlists/example.txt
python -m typo_monitor --data-dir ./data projects
python -m typo_monitor --data-dir ./data scan --project PROJECT_UUID
python -m typo_monitor --data-dir ./data scan --project PROJECT_UUID --discovery-mode cached
python -m typo_monitor --discovery-engine subfinder --discovery-timeout 600 serve
```

Each client's **Scan schedules** panel has two independent cadences:

- **Full enumeration** refreshes discovery, generates uncached seeds, then checks
  DNS and eligible websites. For example, 720 hours means every 30 days.
- **Saved inventory** skips discovery/generation and checks all saved candidates
  with fresh DNS, followed by website checks and capture. For example, 168 hours
  means weekly. This cadence waits until an initial scan saves candidates.

Each interval accepts 0 (off) or 1–8760 hours. Intervals are elapsed hours, not
calendar-month dates. When both are due, enumeration wins and one full scan covers
both. Queueing a full scan advances both enabled cadences; a saved-inventory scan
advances only its own cadence. This applies to manual and scheduled scans.
Schedules and due times persist across restart. Saving unchanged intervals keeps
their deadlines. Stopping a scan leaves schedules enabled and restarts the affected
intervals from its stop time; use **Turn both off** to disable future scans.

Existing single schedules and the server's `--interval-hours` fallback continue
until the project's new form is saved. Saving both intervals as 0 explicitly
opts out of that server fallback. The scheduler runs only while the server is
online, skips clients already queued/running and never scans simulated projects.

The **Subdomains** selector beside **Start scan** chooses whether to enumerate
again or **Use saved inventory** for that manual run. **Default for manual scans**
preselects this choice; each automatic cadence selects its own mode. Each queued
run snapshots its mode and concurrency. See [scan modes](../docs/DISCOVERY.md#choosing-whether-to-enumerate).

## Per-stage SOCKS5 proxies

Each project's **Proxy routes** panel has three independent off/on switches:

1. **Subdomain discovery** sends Subfinder and Assetfinder's provider HTTP(S)
   requests through SOCKS5. The monitor supplies their native HTTP proxy interfaces
   with a private loopback bridge. Amass **4.2.0 is explicitly skipped** while this
   switch is on: its separate resolver traffic is not covered by a provider HTTP
   proxy. No direct Amass process is launched. Turn this switch off to use normal
   three-engine discovery, or select combined/Subfinder/Assetfinder when proxying.
2. **DNS lookups** routes MassDNS A/AAAA/CNAME requests and subsequent DNS parking
   checks over SOCKS5 **UDP ASSOCIATE**. The optional dnspython backend uses the
   same relays. A TCP-only SOCKS server, including a typical SSH dynamic forward,
   is insufficient for this switch. Original upstream resolver IPs, question types
   and ordering/balancing remain unchanged; loopback endpoint/port allowlists are
   validated separately. Proxy/relay errors never become negative DNS evidence.
3. **Website checks + Gowitness** routes the HTTP/title preflight and Chromium's
   HTTP(S) page requests through the same SOCKS5 endpoint. Browser captures keep
   their native `--chrome-proxy` route via a credential-free loopback bridge;
   TLS remains end-to-end. The Linux/POSIX browser launcher disables QUIC and the
   implicit loopback website bypass. Browser control channels stay local. This
   switch can help inspect websites when direct access from the scanner is
   filtered by its firewall.

For a custom proxy, enter `socks5h://host:1080` or `socks5h://user:password@host:1080` for each stage;
`socks5://` is also accepted and uses remote hostname resolution. The same URL
can be used for all three stages. The SOCKS server must be reachable from the
scanner container and support an IPv4 outer connection. In Docker, `localhost`
means the container, not the host or the computer running the web browser.
Remote DNS resolver destinations can still be IPv4 or IPv6.

The switches default to off for existing and new projects. Save them before
queueing a scan; manual/API/scheduled runs snapshot the selected routes and show
those routes in their details. Changing settings does not alter queued/running
work. An empty URL field retains a configured proxy, switching off retains its
URL, and **Clear saved route and turn off** removes it. Saving settings performs
no proxy connection or test. Proxies are never selected implicitly from the
server's `HTTP_PROXY`/`HTTPS_PROXY` environment when a stage is off.

Discovery and website capture also offer **Use Tor · preset address**. The
optional Compose `tor` profile builds a separate non-root client with a private
state volume and no host-published SOCKS/control ports. Its healthcheck reads
local bootstrap/circuit state. Start it and wait for healthy before scanning;
the UI does not launch Docker. The DNS stage rejects the Tor preset because
its UDP transport is unsupported. Amass remains skipped for proxied discovery.
Custom proxy URLs stay saved when switching to Tor, but are hidden while it is
selected. Presets are resolved before queueing, then frozen with each run.
`TYPO_TOR_PROXY_URL` defaults to local port 9050 natively; Compose sets
`socks5h://tor:9050`. `TYPO_WEB_TIMEOUT` exposes the website check timeout to
Compose (default 3 seconds); the Tor guide's example uses 15 seconds for added
latency. Tor itself has no automatic restart policy and all route switches stay
off until explicitly enabled. See [Tor setup](../docs/TOR.md).

Proxy URLs, including credentials, are stored in this project's local SQLite
settings. Inputs are never prefilled with credentials; reports, source metadata,
exports and command arguments contain only redacted endpoint/loopback addresses.
Private URLs are held in worker memory for queued runs and released afterward.
Report deletion keeps project settings; deleting the project removes them.
The optional automation API can start scans using these settings but cannot edit
or retrieve proxy credentials.

A different enabled DNS proxy URL, or switching DNS proxying on/off, makes the
first informative accepted run a fresh DNS baseline. Existing inventory and
historical reports remain; negative-confirmation counters restart and that scan
emits no cross-route DNS changes. Failed runs do not replace the accepted baseline.
The resolver-set comparison guard still applies. Rotating exits may produce
geographic DNS differences even with one saved URL; use a stable DNS exit when
consistent monitoring observations matter.

Routing does not increase configured concurrency or guarantee freedom from
throttling/blocking. IP rotation comes from the provider's configuration, not
SOCKS5 itself. API-key/account/destination and proxy-side limits still apply.
The website preflight retains its configured `--web-timeout` (default 3 seconds);
allow a longer budget when your proxy adds latency. DNS transport failure closes
the affected route; HTTP bridge failures close the connection without synthesizing
a website response, and neither route retries directly.

The image installs pinned **PySocks 1.7.1**. Rebuild/recreate it to include the
dependency and UI changes. Custom credentials are never supplied automatically,
and saving a route never launches Docker or performs a network test. Native
users install the updated requirements. The
implementation uses per-route sockets rather than global socket monkeypatching.
Protocol/library references: [SOCKS5](https://www.rfc-editor.org/rfc/rfc1928),
[PySocks](https://github.com/Anorov/PySocks), and
[Gowitness's pinned proxy flag](https://github.com/sensepost/gowitness/blob/601c84367aaf26eae7d1b5181b70633cb662cf66/cmd/scan.go#L158).

## Rename projects and remove saved reports

Use **Manage project** on the client's page to change its display name. Roots,
IDs, DNS baseline and history are unaffected. The same section offers **Delete
project…**, which removes that client's schedules, inventory, DNS state, reports,
captures and logs. Other clients are unaffected. Demo projects can also be renamed
or deleted.

**Delete report** is available beside finished scans in history and on their
scan detail page. It removes the report's observations, events, screenshots,
AI reviews and run/progress logs. It keeps current inventory/DNS state and cached
generation results. Minimal internal run identity, timing, status and configuration
remain so pruning reports cannot reset the baseline, lose cache references or
change the last schedule attempt. Deleted reports no longer appear in history or
through report/image/API routes. Historical comparisons whose earlier image was
deleted lose that image; future comparisons use the most recent retained image,
or start fresh if no image remains. Exported files outside managed run folders
are not removed.

Deletion uses a separate confirmation page and requires typing `DELETE`. A project
with queued/running work, including a stopped worker still draining, cannot be
deleted or have its reports removed. No existing data is deleted on upgrade.
Artifact cleanup requests are committed with the deletion; interrupted or failed
filesystem cleanup is retried on server restart and logged. SQLite may retain
freed pages for reuse; this is report retention, not secure erasure.

An advisory lock prevents another process from recovering live jobs; use the
GUI for scans while the server is up. Standalone CLI scans can use systemd
timers/cron while the server is stopped, or with a separate data directory.

For Docker configuration, add a Compose override:

```yaml
services:
  monitor:
    command: ["python", "-m", "typo_monitor", "--data-dir", "/data", "--resolver", "1.1.1.1", "serve", "--host", "0.0.0.0", "--port", "5000", "--interval-hours", "24"]
```

Choose **DNS concurrency** when creating a client or on its project page before
starting a scan: an integer from 1 to 128, or blank to inherit the server default
of 24. Each enqueued run freezes its effective count and displays it in run
details; changing the project affects later submissions, including scheduled
ones. MassDNS uses it as the number of simultaneous DNS questions (`-s`),
while dnspython uses it as the number of domain worker threads. The same setting
limits later parking checks. HTTP/text checks and browser captures now have
their own independent concurrency settings.

Concurrency limits outstanding work, not queries per second. The rebuilt
MassDNS **1.1.0+typowatch2** fixes dedicated-resolver ownership in the pinned
upstream release and is capability-checked before a batch starts. A process
failure with no trustworthy DNS domain results now fails the scan and preserves
accepted state, with its signal and diagnostic excerpt visible in source health.
See [DNS crash handling and resolver pools](../docs/DNS.md).

The server default can be set with `--workers 20` before the CLI command, or
`TYPO_DNS_WORKERS=20`. Both Compose profiles pass that environment variable into
the container. A saved project setting takes precedence over the server default.

Both Compose profiles also accept `TYPO_DNS_RESOLVERS` for an explicit pool
and `TYPO_DNS_RESOLVER_MODE=balanced` to distribute hostnames consistently across
it. The default remains ordered failover. An established baseline keeps its
resolver view pinned; use a new project to change that view after informative
DNS results have been accepted.

Discovery uses `--discovery-engine combined` by default. Set that option to
`amass`, `subfinder` or `assetfinder` for a single adapter. The combined tools
have independent per-root deadlines; one slow or failed tool cannot discard
another's valid names. `--discovery-timeout` is a per-tool, per-root limit in
seconds, defaulting to 600. The corresponding environment variables
are `TYPO_DISCOVERY_ENGINE` and `TYPO_DISCOVERY_TIMEOUT`; both Compose profiles
pass them into the container. Historical runs keep the engine recorded when
they ran. Changing discovery engine does not discard saved seeds/candidates or
replace the DNS comparison baseline.

The DNS backend defaults to `--dns-backend massdns` (`TYPO_DNS_BACKEND=massdns`).
Both Compose profiles pass that environment setting. Use `--dns-backend dnspython`
explicitly for the Python implementation. Neither backend silently falls back
to the other. Native MassDNS runs require the binary on PATH or `--massdns-path`.
Every saved candidate still receives fresh A, AAAA and CNAME questions; missing
output, terminal query failures, truncated responses and contradictory answers
remain uncertain. Only explicit negative results can advance missing-domain
confirmation. Resolver addresses and comparison rules remain consistent with
the stored baseline. See [bulk DNS details](../docs/DNS.md).

Other global options: `--workers` (default concurrency 24), `--dns-timeout`
(default 4 seconds for a query's retry budget), `--massdns-timeout` (default
3600 seconds for the entire bulk job), and `--max-candidates` (250,000).
Exceeding the candidate limit fails a run rather than truncating coverage.
Both Compose profiles accept `TYPO_MAX_CANDIDATES` for this limit, defaulting to
`250000`; `--max-candidates` overrides that default in a native invocation.
The count is the number of unique hostnames awaiting DNS checks, not the number
of resolving domains. A discovery result can expand into thousands of typo
candidates. Before failing this guard, the run records the seed/candidate counts
in `generation.json`; the saved inventory and DNS baseline remain unchanged.
`discovery-hostnames.txt` in the live output shows the filtered in-scope names
from discovery, separately from Amass's raw asset graph. IPs, networks, ASNs and
unrelated infrastructure cannot become discovery seeds; A/AAAA record values
still contain their legitimate IPv4/IPv6 addresses after fresh DNS validation.
AIL generation has a 15-minute timeout; each root's discovery call defaults
to a 10-minute timeout. The current discovery/streaming changes have not been built
or tested here.


Permutation completion is cached in SQLite per seed and generator profile. The
fingerprint covers AIL version/mode/settings, tldextract and inflect versions,
bundled suffix/data hashes and the adapter implementation epoch. Changing those
inputs regenerates retained seeds; adding one discovered seed generates only
that seed. Generation markers publish with the accepted inventory/provenance in
one transaction, so failed or interrupted runs do not poison the cache. Existing
databases and imported inventories regenerate retained seeds once after upgrade
because they have no trusted completion markers. Historical candidates remain
monitored even if an updated generator produces fewer names. See
[incremental generation](../docs/DISCOVERY.md#incremental-permutation-generation).

## Bring forward legacy inventory

Stop the app first and use a new project name:

```sh
python -m typo_monitor --data-dir ./data import-legacy --name "Example migrated" --domains domainlists/example.txt --output /path/to/old/output/example
```

The importer reads known domain-list artifacts from current output and backups.
It unions discovered/combined seeds and deduplicated/checked candidates. Invalid
generated hostnames are excluded and counted. Existing files, screenshots, and
spreadsheets are left in place.

Imported inventory starts unchecked; the next fresh scan establishes a baseline.
Old XLSX rows are not treated as reliable history because they do not establish
whether missing domains were actually checked. For container import, mount the
old output read only and use a one-off container while the server is stopped.

## Offline preview and checks

```sh
python -m typo_monitor --data-dir ./demo-data demo
python -m typo_monitor --data-dir ./demo-data serve
python -m unittest discover -s tests -v
```

The demo is explicitly simulated and makes no external queries. Simulated
projects cannot be scanned or scheduled, so fixture DNS cannot become a live
comparison baseline. Use a separate data directory for previews.

Each real run has a UUID folder under `data/runs`, with candidates, source
metadata and raw observations. Runs that generate new permutations also retain
the generated output and tool log; unchanged seeds reuse SQLite inventory. SQLite is the source of
truth for projects, comparison state, observations, and events. CSV exports the
current inventory with last-known records and uncertainty; it is not a baseline.

The new interface includes searchable/paginated inventory, source health, run
history, before/after records, and CSV. The default review view shows only
currently resolving typo candidates and excludes original roots/subdomains.
Client projects appear in the sidebar throughout the application. Selecting a
client opens only its findings, scan history and exports; Overview summarizes
the full workspace. **New project** opens a dedicated creation page.
Source groups trace each candidate back to the input domain or subdomain that
generated it; candidates can belong to multiple groups. Full inventory and
uncertain/absent results remain available through the filters and are rechecked
on subsequent scans. Legacy candidates with no generation provenance are shown
as Unattributed until their first fresh generation supplies that association.

An optional **Hide likely parked** filter uses parking-specific NS/CNAME evidence
from known providers. Its evidence is inspectable; ordinary GoDaddy DNS and
shared IPs are not enough to hide a domain. Parking is refreshed each scan and
does not alter the DNS change history. This is a DNS heuristic, not a website
content check or a claim that a domain is safe. See [parking rules](../docs/PARKING.md)
and [discovery options](../docs/DISCOVERY.md).

The default gallery shows dated HTTP/HTTPS captures. Candidate review includes
full images, previous/current comparisons, original-source reference captures,
and attempt history. Failed attempts can display a clearly dated older image.
Distinct HTTP/HTTPS bodies have separate screenshots; matching complete HTML
shares one selected capture. The manual comparison view
shows earlier/current images without calculating hashes or change verdicts.
Automatic change detection uses static text and endpoint metadata only.

The optional n8n Cloud workflow calls the server's token-protected API rather
than trying to run Linux tools inside n8n. Set `TYPO_MONITOR_API_TOKEN` to at least
32 characters to enable it; without that setting all `/api/` routes stay disabled.
Metadata requests return only new/changed captures after safe duplicate filtering.
Image bytes require an explicit authenticated request for one domain and protocol.
Stored AI assessments remain distinct from local comparisons and DNS findings.
See [n8n setup](../docs/N8N.md) and [capture details](../docs/SCREENSHOTS.md).

To test real browser capture without visiting any external site:

```sh
python tests/capture_smoke.py --gowitness /path/to/gowitness --chrome /path/to/chromium --driver gorod
```

Embedded XLSX reporting remains in the historical pipeline. Live-scale scanning, container runtime,
native Windows, and authenticated multi-user deployment need validation in their
intended environments.
