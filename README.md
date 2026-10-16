# Typo Watch

Linux/server monitoring for typo domains, using AIL permutations and optional
Subfinder discovery. The current application lives in
[monitor](monitor/README.md).

V3 now stores observations and an accumulating candidate inventory in SQLite.
Discovery misses do not remove candidates, DNS failures remain uncertain, and
changes compare normalized DNS record sets instead of spreadsheet positions.

The Flask interface provides projects, a screenshot gallery, previous/current
visual review, inventory search, scan history, source health, and CSV export.
Docker Compose supplies an isolated Linux test/deployment
environment with a persistent data volume; a Python virtual environment also works.

For a separate local run without n8n or AI, use the [standalone folder](standalone/README.md).
It provides its own data directory, an offline screenshot demo, and HTML/JSON
reports measuring a small handoff batch before any cloud connection.

```sh
cd "monitor"
docker compose up --build -d
```

Open <http://127.0.0.1:5000>. See the [application guide](monitor/README.md)
for native setup, scheduling, migration, and current limits. The old shell
installers and V1/V2 scripts are retained as historical sources; the new image
does not execute them.

Gowitness captures both HTTP and HTTPS and preserves dated image history. Local
pixel comparison tracks changes and collapses identical protocol images in the
gallery. The [n8n Cloud workflow](workflows/n8n-visual-review.json) can orchestrate
the server over HTTPS and send a small selected batch to n8n's OpenAI image node.
AI starts disabled; local image comparison works without it.
Embedded XLSX reporting remains in the historical scripts.
The [audit](docs/AUDIT.md) explains the original failure modes and tool choices.

## Repository layout

| Folder | Contents |
| --- | --- |
| [`legacy/`](legacy/ARCHIVE.md) | Every original file, preserved from commit `eff48ca`. |
| [`monitor/`](monitor/README.md) | Current Python scanner, GUI, screenshots, tests and Docker setup. |
| [`standalone/`](standalone/README.md) | Local runner with its own data and handoff reports, without n8n. |
| [`workflows/`](workflows/n8n-visual-review.json) | Optional n8n workflow and suggested AI prompt. |
| [`docs/`](docs/AUDIT.md) | Design audit and configuration guides. |

Start locally without n8n:

```sh
python3 standalone/run.py setup
python3 standalone/run.py demo
python3 standalone/run.py serve --port 5055
```

The demo uses labeled local fixtures. Real projects run their discovery, DNS and
browser checks on your Linux host. Full screenshots stay local; the optional
handoff sends only selected image copies and defaults to five pairs per batch.

