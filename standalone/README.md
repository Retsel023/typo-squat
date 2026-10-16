# Local runner, without n8n

This folder is a separate local testing profile for the current V3 application.
It keeps its own `data/` (SQLite, scan artifacts and full screenshots) and
`reports/` (small HTML/JSON handoff previews). It shares the maintained Python
code in V3, so fixes apply to both native and Docker runs.

No n8n installation, Docker daemon, OpenAI account or model is needed. The
launcher disables the optional automation API even if its token exists in your
shell. Scanning and screenshots still use their normal network connections;
the demo and handoff report operate entirely on local fixtures/files.

## See the current progress

From the repository root on Linux:

```sh
python3 standalone/run.py setup
python3 standalone/run.py demo
python3 standalone/run.py serve --port 5055
```

Open <http://127.0.0.1:5055> and select the **Simulated demo** project. The gallery
contains labeled example screenshots, original references, before/after changes,
HTTP/HTTPS duplicate collapse and failed-capture states. These are simulated
observations, not findings about real domains. The demo also creates
`standalone/reports/demo.html` and `demo.json`; open the HTML file to see the
first five pairs that would qualify for optional AI review and their image size.

`setup` creates a virtual environment here and installs the locked Python
dependencies. If the repository already has a working `.venv`, you can skip
setup; the launcher uses it. It never installs Linux system packages or scanner
binaries. For real screenshots, install Gowitness **3.2.2** and Chrome/Chromium;
Subfinder is optional discovery. Run `python3 standalone/run.py doctor` to check
what is available. The [V3 guide](../monitor/README.md) documents
those dependencies and scanning options.

## Run your own project

Create a UTF-8 text file containing your root domains, one per line. Either create
the project in the local UI, or run a single scan from this folder:

```sh
python3 standalone/run.py scan --name "My project" --domains /path/to/domains.txt
python3 standalone/run.py projects
python3 standalone/run.py report --project PROJECT_UUID
```

Use `--project PROJECT_UUID` on later `scan` commands to preserve its inventory
and baseline. The server offers manual scans; optional built-in scheduling needs
no n8n: `python3 standalone/run.py serve --port 5055 --interval-hours 24`.
Stop the server before running the CLI scanner against the same data directory;
the UI and the single-run CLI use the same exclusive worker lock. Reports can be
generated while the UI is open.

Global scanner options go **before** the command, for example:

```sh
python3 standalone/run.py --gowitness-path /path/to/gowitness --chrome-path /path/to/chromium serve --port 5055
```

## Check volume before connecting n8n

```sh
python3 standalone/run.py report --run RUN_UUID --limit 5
python3 standalone/run.py report --run RUN_UUID --limit 5 --offset 5 --output standalone/reports/next
```

The HTML/JSON report includes counts for selected and excluded captures and the
measured image bytes for that batch. It never contains embedded images and makes
zero external requests. It counts repeated source references and base64 overhead;
prompts and HTTP/JSON overhead are additional. Byte counts do not estimate tokens
or price. A first scan can produce many new candidates, so begin with five.

The shared local selection excludes unchanged images, equivalent HTTP/HTTPS
review pairs, original-domain captures, failed/uncertain comparisons, likely
parking pages and captures with a saved AI review. Parked sites remain available
in the local gallery. Each selected pair can include current, previous and one
original-reference image. Optional handoff copies are at most 1280 pixels on
their longest edge and 256 KiB each; full-resolution evidence stays on disk.
Smaller copies can obscure fine text, so use the local originals for close review.

The [separate n8n workflow](../docs/N8N.md) is optional and starts with AI disabled.
Nothing in this folder uploads to it. The local scanner does not run an AI model;
its change detection and duplicate checks use image pixels.
