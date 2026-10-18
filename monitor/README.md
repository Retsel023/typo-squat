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
only; writable scratch space is provided at `/tmp`.

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
DNS, parking, screenshot and image-comparison stages. DNS progress includes
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
Streaming browser captures also have an independent 60-second per-page timeout.
The Docker image already includes the required capture tools.

Before Gowitness, lightweight HTTP and HTTPS checks test each resolving domain
on ports 80 and 443. Only responding endpoints reach the browser. Any HTTP
status qualifies, including redirects, 403 and 404; timeouts remain uncertain.
Use `--web-timeout` to change the 3-second check timeout. Probe concurrency uses
the run's DNS concurrency setting, independently of the 4 browser workers. Results are
saved in `preflight.json` and refreshed on every run. Domains without a responding
website remain in DNS inventory, with compact status rows instead of empty
screenshot frames. An older saved screenshot is explicitly labelled as previous.

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

Each client's project page has its own scheduling control. Set a positive
interval to repeat that client's scans, or choose manual/off to disable its schedule.
New clients inherit the server's `--interval-hours` default until a client interval
is saved. An explicit manual/off setting also overrides a positive server default. Per-client intervals and next due times
persist in SQLite; they survive a restart. A manual scan advances that client's
next due time so it is not immediately followed by a scheduled duplicate.

The **Subdomains** selector beside **Start scan** chooses whether to enumerate
again or **Use saved inventory**. Saved inventory skips enumeration and typo
generation; every saved candidate still receives fresh DNS checks, including
previously non-resolving candidates. A project needs saved candidates first.
**Default scan mode** in the schedule form is persisted for scheduled scans
and preselected for manual scans. Save it with an interval of 0 to keep scans
manual. The chosen mode is frozen when each run is queued and shown in run
details. Select enumeration periodically to discover new seeds or apply a new
generation profile. See [scan modes](../docs/DISCOVERY.md#choosing-whether-to-enumerate).

The server must remain running for schedules to execute. The scheduler checks
for due clients periodically, skips clients that are already queued/running and
skips simulated demo projects. Stopping a scan does not disable its future
schedule; its next attempt moves one interval after the stop time to prevent an
immediate overdue restart. Turn scheduling off separately if needed. The global fallback uses
persisted last-attempt times, including failed, partial and cancelled attempts,
to avoid immediate retry storms. New clients can be scanned manually or wait
until due.

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
limits later parking and website checks. Browser capture concurrency remains
separate.

The server default can be set with `--workers 20` before the CLI command, or
`TYPO_DNS_WORKERS=20`. Both Compose profiles pass that environment variable into
the container. A saved project setting takes precedence over the server default.

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
Exact HTTP/HTTPS duplicates share one gallery image; both raw captures remain.
Similar images are labeled as similar. Any changed decoded pixels remain a
local image change, not an automatic impersonation verdict.

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
