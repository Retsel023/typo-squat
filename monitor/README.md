# Typo Watch v3

Linux server monitoring with Docker as an isolated test/deployment environment.
Python owns orchestration, persistent state, DNS checks, and the web interface.
AIL supplies the full permutation algorithms; Subfinder remains an optional
passive discovery adapter.

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
Only one run per project can be accepted at once.

The image uses slim Python, versioned Subfinder and Gowitness binaries, Chromium,
locked Python dependencies, and an unprivileged user. It does not run Kali upgrades, the old
installers, cron, or shell command queues. SQLite and per-run artifacts live in
the `monitor-data` named volume at `/data`. The application filesystem is read
only; writable scratch space is provided at `/tmp`.

Stop with `docker compose down`. Keep the named volume to keep history. Back up
the volume while the application is stopped; copy the entire data directory,
including any SQLite WAL/SHM files. `down -v` removes the volume and its history.

Compose binds to host loopback. For a remote server, use an SSH tunnel or an
authenticated HTTPS reverse proxy. The application has CSRF protection and
escaped output but does **not** provide GUI user accounts. The optional automation
API has separate Bearer-token authentication; expose only `/api/` for n8n Cloud
and keep the GUI behind your own access controls.

## Run in a virtual environment

Use Python 3.10 or newer (the Docker image uses 3.12):

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m typo_monitor doctor
.venv/bin/python -m typo_monitor serve
```

No root access or system package installation is needed. Install Subfinder
separately on `PATH` to enable discovery; its provider/API configuration follows
Subfinder's normal configuration. If unavailable, a scan shows discovery gaps
and still checks roots and retained inventory. Use `--no-discovery` to
intentionally disable discovery instead.

Install Gowitness 3.2.2 and Chrome/Chromium for native capture, or specify their
paths explicitly:

```sh
python -m typo_monitor --gowitness-path /path/to/gowitness --chrome-path /path/to/chromium serve
```

Captures are enabled by default. `--no-screenshots` explicitly skips them while
DNS monitoring continues. `--capture-workers` defaults to 4, `--capture-timeout`
to 900 seconds per batch, and `--capture-driver` to `gorod`; `chromedp` is also
available. Missing binaries and individual HTTP/HTTPS failures are displayed.
The Docker image already includes the required capture tools.

The Python orchestration avoids Bash, cron, `flock` binaries, and MassDNS.
Native Windows compatibility has not been tested; Linux is the target.

## What comparisons mean

* Roots and previously discovered seeds are retained. Candidates are the union
  of previous inventory and current AIL output, rather than a replacement.
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
  Interrupted jobs are marked failed on restart. Graceful shutdown cancels
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
```

The interval uses persisted last attempt times, including failed/partial runs,
to avoid retry storms. New projects wait one interval or can be scanned manually.
Only the server process runs the schedule. An advisory lock prevents another
process from recovering live jobs; use the GUI for scans while the server is up.
Standalone CLI scans can use systemd timers/cron while the server is stopped, or
with a separate data directory.

For Docker configuration, add a Compose override:

```yaml
services:
  monitor:
    command: ["python", "-m", "typo_monitor", "--data-dir", "/data", "--resolver", "1.1.1.1", "serve", "--host", "0.0.0.0", "--port", "5000", "--interval-hours", "24"]
```

Other global options: `--workers` (default 24 DNS workers), `--dns-timeout`
(4 seconds per query), `--max-candidates` (250,000). Exceeding the candidate limit
fails a run rather than truncating coverage. AIL generation has a 15-minute
timeout; each root's Subfinder call has a 3-minute timeout. Python DNS trades
MassDNS speed for explicit error handling; tune workers for the resolver/server.

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

Each real run has a UUID folder under `data/runs`, with candidates, generated
output, tool logs, source metadata, and raw observations. SQLite is the source of
truth for projects, comparison state, observations, and events. CSV exports the
current inventory with last-known records and uncertainty; it is not a baseline.

The new interface includes searchable/paginated inventory, source health, run
history, before/after records, and CSV. The default review view shows only
currently resolving typo candidates and excludes original roots/subdomains.
Source groups trace each candidate back to the input domain or subdomain that
generated it; candidates can belong to multiple groups. Full inventory and
uncertain/absent results remain available through the filters and are rechecked
on subsequent scans. Legacy candidates with no generation provenance are shown
as Unattributed until a fresh generation supplies that association.

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
