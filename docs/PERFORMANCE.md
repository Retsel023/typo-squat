# Website and screenshot performance

Gowitness already runs concurrent page captures in one browser/worker process;
more monitor containers on the same laptop do not add CPU, RAM or bandwidth.
The scanner previously fixed browser concurrency at four unless the native CLI
flag was changed. DNS concurrency did not raise browser concurrency.

## Per-project controls

Open **Screenshot and report policy → Website and browser performance** before
starting a scan. Fields may be left blank to inherit the shown server default.
Manual and scheduled submissions freeze their effective values at queue time.
Changing a project never changes a queued or running scan. Run headers and
browser progress show the chosen values.

| Control | Range | Server default | Purpose |
| --- | --- | --- | --- |
| Concurrent browser captures | 1–32 | 4 | Outstanding Gowitness page tasks; HTTP and HTTPS each count as one task. |
| Browser timeout per page | 5–180 seconds | 60 | Bounds slow navigation/browser operations for each target. |
| Wait before screenshot | 0–30 seconds | 3 | Extra wait after navigation, before capturing content. Must be shorter than the page timeout. |
| Concurrent HTTP/text checks | 1–128 | 24 | Lightweight preflight/extraction workers, independently of DNS and browsers. |

Try **8 browser captures and a 1-second screenshot wait** as a starting point,
then increase gradually if CPU/RAM allow. This is a tuning suggestion, not a
measured speedup. A 30-second page timeout can free slow slots sooner, but will
fail pages that need longer. A shorter screenshot wait can omit late-loading
content. Tor or other slow proxies may need longer page and HTTP timeouts.

The pinned [Gowitness 3.2.2 CLI](https://github.com/sensepost/gowitness/blob/601c84367aaf26eae7d1b5181b70633cb662cf66/cmd/scan.go)
exposes `--threads`, `--timeout` and `--delay`; the
[gorod driver](https://github.com/sensepost/gowitness/blob/601c84367aaf26eae7d1b5181b70633cb662cf66/pkg/runner/drivers/go-rod.go)
applies a per-page timeout and waits after navigation. Both the streaming and
DNS-first adapter paths now pass the same explicit settings. A lower page
timeout does not change the separate batch/drain deadline.

DNS remains fresh every scan. Browser concurrency does not change MassDNS
concurrency. HTTP/text concurrency is no longer derived from DNS concurrency.
Unchanged content still skips browser work when its saved baseline qualifies.
Automatic image change detection remains removed; screenshots are for humans.

## Server defaults and Docker

Project overrides take precedence. Set a project field back to blank when you
want it to follow a new server default. Compose and native CLI use these values:

| Environment variable | Native global flag | Default |
| --- | --- | --- |
| `TYPO_CAPTURE_WORKERS` | `--capture-workers` | 4 |
| `TYPO_CAPTURE_PAGE_TIMEOUT` | `--capture-page-timeout` | 60 |
| `TYPO_CAPTURE_DELAY` | `--capture-delay` | 3 |
| `TYPO_WEB_WORKERS` | `--web-workers` | 24 |
| `TYPO_WEB_TIMEOUT` | `--web-timeout` | 3 |
| `TYPO_CAPTURE_TIMEOUT` | `--capture-timeout` | 900 |
| `TYPO_BROWSER_SHM_SIZE` | Compose only | 256mb |

The capture deadline is seconds after streamed input closes, or the whole
browser invocation in DNS-first mode. Raise it for large batches if the
remaining work cannot finish in 900 seconds. Timeout failures keep explicit
status/logs; a fast run is not proof that every screenshot succeeded.

With more browsers, you can raise shared memory to `512mb` or `1gb`, subject to
available RAM. This changes shared-memory capacity, not available CPU or total
RAM. Observe actual use with `docker stats` while you run your own scan.

After finishing/stopping the current scan, a standalone example preserving your
previous candidate/resolver configuration is:

```sh
cd "$HOME/Downloads/chatgpt projects/typo squat/repository/standalone"
TYPO_STANDALONE_PORT=5057 \
TYPO_MAX_CANDIDATES=1000000 \
TYPO_DNS_RESOLVERS="1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4" \
TYPO_DNS_RESOLVER_MODE=balanced \
TYPO_CAPTURE_WORKERS=8 \
TYPO_CAPTURE_PAGE_TIMEOUT=30 \
TYPO_CAPTURE_DELAY=1 \
TYPO_CAPTURE_TIMEOUT=3600 \
TYPO_WEB_WORKERS=24 \
TYPO_BROWSER_SHM_SIZE=512mb \
docker compose up --build -d --force-recreate monitor
```

If using the Tor profile, keep your `TYPO_WEB_TIMEOUT=15` setting and replace
the final line with `docker compose --profile tor up --build -d --force-recreate monitor tor`.
Existing project overrides still win. Put persistent defaults in your existing
Compose `.env` file if desired; keep your current DNS, port and proxy settings.
These are commands for you to run; no build, container change or performance
benchmark was executed while implementing this update.

## Additional containers or another machine

Do not use `docker compose --scale monitor=...` with this application's current
Compose setup. The HTTP port, persistent SQLite data and exclusive worker lock
belong to one scanner service. Cloning that service does not partition a run.

Actual offloading to another server would need a shared task queue, separate
browser workers, unique target ownership, artifact transfer and reliable
cancellation/result collection. That architecture is not implemented here.
The present improvement increases bounded parallelism within the existing
scanner and avoids launching a browser for unchanged pages.
