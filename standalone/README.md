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
also controls the subsequent DNS parking and website checks; browser captures have a
separate worker limit. Each queued scan keeps its chosen count, so editing a
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
up to 64 KiB of uncompressed HTML and following at most three redirects within
the probe's timeout budget. They use the same website proxy as Gowitness.

Only complete titles on final 2xx responses can skip a screenshot. Missing or
unreadable titles and HTTP errors still reach Gowitness. JavaScript-only titles
need the browser. Original roots and discovered source subdomains bypass title
exclusions to preserve references. Excluded endpoints keep their DNS inventory,
title, reason and whether the rule was global or project-specific; later scans
check them again. Previous images remain saved.
The run report counts title exclusions separately from failures, and no image
is sent for them in the n8n review queue. Use specific phrases: titles alone do
not establish whether a site is safe. Changes apply to newly queued manual and
scheduled scans. Each run saves both lists when queued and displays those
rules in scan details. Queued/running scans keep their original settings.
Title comparisons continue when both exclusion lists are off.

Routine scans now default to **Changes only**. They compare static HTML titles
against the previous accepted run, separately for HTTP and HTTPS. An unchanged
title and matching HTTP endpoint can skip Gowitness when its matching successful
image baseline is still available. Missing/uncertain titles, missing baselines,
prior capture failures, changed titles/endpoints and new websites still reach
the browser. Existing reports without static title data need a fresh baseline.

Use **Latest report** for the website changelog: it shows new or changed
observations, before/after titles and only images actually captured in that run.
Unchanged sites do not repeat old screenshots. DNS changes have their own
section; a change is not proof of a domain purchase. The complete project
inventory and prior reports stay available separately.

Choose **Full capture / report** beside **Start scan** for all eligible endpoints.
It is independent of enumeration. The **Screenshot and report policy** panel
sets the manual default and a periodic recapture age: 30 days by default,
0 to disable, up to 365. A page can change without changing its title; periodic
or full captures can detect that, while identical images stay out of change
reports and the AI queue. Both schedule cards have a screenshot/report selector,
so monthly enumeration/full capture can accompany weekly cached/changelog runs.
Queued and running scans retain their saved policy. Global/project exclusion
phrases apply in both modes.

MassDNS can feed this work before its bulk DNS job finishes. A domain is offered
only after its A, AAAA and CNAME questions are complete and the positive result
is validated. Bounded HTTP/HTTPS checks pass responsive URLs to one Gowitness
process through standard input. A full handoff queue defers names until the
final DNS pass, so slow browsers do not block DNS or lose names. Final captures
must belong to domains that resolve in the completed DNS results; accepted
findings still publish together at the end. Stop scan discards unfinished work.
The dnspython alternative remains DNS-first. Live pipeline progress displays
separate DNS, web-check and capture counts.

## Follow an actual scan

```sh
docker compose logs -f --tail=100 monitor
```

Logs include the run UUID and transitions through discovery, generation/reuse,
DNS, parking, screenshots and image comparison. DNS progress reports checked,
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
qualify for optional AI review and their measured image size. Repeating `demo`
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

The HTML/JSON report contains counts of selected/excluded captures and measured
image bytes. It contains no embedded screenshots and makes zero external
requests. Repeated reference images and base64 overhead are counted; prompts and
HTTP/JSON overhead are additional. Byte counts do not estimate tokens or price.
A first scan may produce many new candidates, so begin with five pairs.

The shared selection excludes unchanged images, equivalent HTTP/HTTPS review
pairs, original-domain captures, failed/uncertain comparisons, likely parking
pages and captures with a saved AI review. Parked sites remain in the gallery.
Each selected pair can include the current capture, a previous capture and one
owned reference. Optional handoff copies are bounded to 1280 pixels on their
longest edge and 256 KiB each; full-resolution evidence remains on disk. Smaller
copies can obscure fine text, so inspect local originals for close review.

The [separate n8n workflow](../docs/N8N.md) is optional and starts with AI disabled.
It uses n8n's native OpenAI image-analysis node when enabled. Nothing in this
standalone profile runs an AI model; local change detection and duplicate checks
compare image pixels.

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
