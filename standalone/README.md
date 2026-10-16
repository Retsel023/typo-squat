# Standalone scanner with Docker

This folder runs the current application without n8n or local AI. Docker builds
from the shared [`monitor/Dockerfile`](../monitor/Dockerfile), including Python,
Subfinder, Gowitness **3.2.2**, Chromium and the locked Python dependencies. You
need Docker Engine and the Compose plugin on the host; you do not need to install
Python, Go, Chromium or scanning tools there. Keep this folder beside `monitor/`
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

Each client's project page can save its own scan interval or select manual/off.
New clients follow the server default until their own schedule is saved. Explicit
manual/off overrides a server-wide interval.
These settings and the client's next due time persist in the named volume. Keep
the server container running for schedules to execute. A manual scan advances
the next due time; **Stop scan** stops the current attempt but leaves the future
schedule enabled. Stopping restarts its interval from the cancellation time,
preventing an overdue scan from immediately restarting. Disable the schedule
separately when desired. Simulated demo projects are never automatically scanned.

## Follow an actual scan

```sh
docker compose logs -f --tail=100 monitor
```

Logs include the run UUID and transitions through discovery, generation/reuse,
DNS, parking, screenshots and image comparison. DNS progress reports checked,
resolved, negative and uncertain counts. These are stage/count updates, not an
estimated completion time. The run page refreshes its status while work runs;
accepted findings appear after the run completes.

Tool-specific output is stored under `/data/runs/RUN_UUID/`. Once screenshot
capture has started, inspect its log without installing host tools:

```sh
docker compose exec monitor tail -n 50 /data/runs/RUN_UUID/gowitness.log
```

Generation attempts also retain `generator.log`; discovery retains per-root
stderr logs. A reused generation cache does not launch AIL or create a new AIL
log. For native runs, the same application stage messages appear in the terminal
and tool logs live under `standalone/data/runs/RUN_UUID/`.

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
install Gowitness **3.2.2** and Chrome/Chromium; Subfinder provides optional
discovery. The [application guide](../monitor/README.md) documents these tools.

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

The Docker configuration reuses the maintained image definition. The image has
been built successfully, and its bundled scanner tools passed `doctor` in a
disposable container using the read-only application filesystem.
