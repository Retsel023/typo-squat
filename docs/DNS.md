# Bulk DNS checks

The default pipeline combines Amass, Subfinder and Assetfinder discovery, uses AIL to generate typo
candidates, and MassDNS to check the retained candidate list. Python coordinates
the tools, validates observations, saves changes and serves the UI. Generation
is cached per seed/profile; every saved candidate still receives fresh DNS
checks on every scan.

## One bulk lookup job

The application passes the full deduplicated candidate file to one MassDNS
process with A, AAAA and CNAME query types. It reads newline-delimited JSON as
results arrive, including terminal failures. The UI reports completed domains
after all three questions have outcomes; query counts show the work within
that stage. This is not an overall scan percentage.

**DNS concurrency** controls MassDNS's simultaneous questions (`-s`), from 1 to
128. It is not a process/thread count. Each run freezes the saved client setting,
or the server default (`--workers`, `TYPO_DNS_WORKERS`, otherwise 24). The same
setting bounds later parking and website checks. Gowitness has its own capture
concurrency. This is an outstanding-request limit, not a queries-per-second
limit: fast positive or negative replies can still produce high throughput.

The image pins [MassDNS v1.1.0](https://github.com/blechschmidt/massdns/releases/tag/v1.1.0)
at commit `ca8114164361f6a296399d8160bb07d55bdc4843`. Its
[upstream JSON format and flags](https://github.com/blechschmidt/massdns/blob/v1.1.0/src/main.c)
are used directly, with explicit resolver addresses, bounded retries, response
source verification and no success-only output filter. The Docker build applies
the repository's JSON completeness and resolver-ownership patch, identifying
the image binary as **1.1.0+typowatch2**. It preserves the original DNS
section counts, parsing completeness and raw DNS wire bytes. Python strictly
decodes those bytes before accepting records; it does not trust the tool's
rendering of record data. Native MassDNS
installations need that same patch; an unmodified binary is not silently used
with weaker validation. The adapter checks `--version` for `typowatch-json/1`
and `safe-resolvers/1` before starting its DNS batch; older patched binaries
need rebuilding. The dnspython backend remains an explicit alternative.

The ownership patch fixes the pinned release's completion path, which puts a
lookup back into its pool and calls `can_send()` before cleaning its resolver
allocation. The lookup may already have been reused by then. It now releases
ownership before reuse, retains the parser's reference while scheduling all
record types for a name, and releases references for rejected duplicate lookups.
This addresses a concrete memory-corruption path used by extended input, not
a change to DNS response acceptance. This source change has not been run or
compiled here.

## Reliable observations

Every candidate must have an outcome for A, AAAA and CNAME. Missing output,
malformed or conflicting results, truncated responses and terminal query
failures remain uncertain. Silence is never interpreted as NXDOMAIN.
Uncertain checks retain accepted records and cannot confirm disappearance.
Explicit negatives still require consecutive confirmation under the stored
comparison rules.

Only answers for the candidate or a validated CNAME chain rooted at it can
supply addresses. Unrelated answer/additional records cannot become candidate
findings. Only the candidate's direct CNAME targets enter its stored CNAME
record set. TTLs and response ordering do not create record changes.

The default `ordered` mode supplies the pinned recursive addresses in their
configured preference order through MassDNS extended input. Opt-in `balanced`
mode rotates the same pool by a stable SHA-256 hash of each hostname. A, AAAA
and CNAME start with the same resolver for a given hostname; retries move through
its remaining preference order within the bounded retry count. The canonical
pool and mapping stay stable across runs, rather than randomly switching each
hostname's preferred server. Both modes verify response sources and wire data.

Keep resolvers consistent and use servers with the same DNS view. Changing
resolver addresses or switching to/from balanced mode requires a new project
baseline once an informative baseline exists. A project whose previous DNS
results were entirely uncertain has no informative baseline yet and can change
its configuration. Discovery-engine changes never remove saved candidates.

## Settings and output

Global options precede the command:

```sh
python -m typo_monitor --dns-backend massdns --workers 20 serve
python -m typo_monitor --massdns-path /path/to/massdns serve
python -m typo_monitor --dns-backend dnspython --workers 20 serve
python -m typo_monitor --resolver 1.1.1.1 --resolver 8.8.8.8 --resolver-mode balanced serve
```

Both Compose profiles accept `TYPO_DNS_RESOLVERS` (comma- or whitespace-separated
IP addresses, up to 16) and `TYPO_DNS_RESOLVER_MODE` (`ordered` by default, or
`balanced` for MassDNS). Explicit repeated CLI `--resolver` arguments override
the environment pool. An empty pool setting retains the system DNS configuration.
For example, the standard resolver addresses documented by
[Cloudflare](https://developers.cloudflare.com/1.1.1.1/ip-addresses/) and
[Google](https://developers.google.com/speed/public-dns/docs/using) can be supplied:

```sh
TYPO_DNS_RESOLVERS="1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4" \
TYPO_DNS_RESOLVER_MODE=balanced TYPO_STANDALONE_PORT=5057 \
TYPO_MAX_CANDIDATES=1000000 docker compose up --build -d --force-recreate monitor
```

Use this from `standalone/`; keep the chosen values in its `.env` for later
Compose invocations. An existing saved client concurrency of 100 still overrides
a server default of 20: save the lower value on the client before queueing.
More resolver addresses spread work in balanced mode; they do not set a QPS
ceiling or establish that a provider is rate limiting. Website preflight and
Chromium still perform their own hostname resolution using the container's
system resolver; MassDNS supplies eligibility and recorded DNS evidence.

`TYPO_DNS_BACKEND` selects the backend and is passed by both Compose profiles.
Missing MassDNS does not silently select Python. Native runs need the external
binary; Docker builds include it. The Python option uses domain worker threads
for its requests and the same observation/comparison contract.

`--dns-timeout` defaults to 4 seconds and supplies the query retry budget;
MassDNS derives a retry interval for its bounded attempts. `--massdns-timeout`
defaults to 3600 seconds for the entire bulk job. The Stop button terminates the
external process group and prevents unfinished observations being published.

Raw output is retained under `data/runs/RUN_UUID/massdns.jsonl` with diagnostics
in `massdns.stderr.log` and the binary capability check in `massdns.version.txt`.
Wire-inclusive output has an 8 GiB per-run safety cap, raised from 1 GiB to
accommodate large three-type inventories; this is a cap, not preallocated space.
The input and resolver files remain per-run artifacts
but are excluded from the live-output viewer. The viewer shows bounded tails;
the observation parser reads complete records, independently of that display.

Negative subprocess return values are reported by signal name, such as
`SIGABRT` for an abort. They are process failures rather than proof of resolver
rate limiting. The source card includes the process signal, completed question
counts and a bounded diagnostic excerpt. Progress does not mark unanswered
questions as completed when a child dies. If no trustworthy complete domain
result remains, the run fails and keeps the previously accepted inventory and
baseline; it does not claim completion with gaps or replace state with an
all-unknown result. Independently validated results from an interrupted batch
can still be retained as partial findings. Historical runs are not rewritten.

These backend changes have not been built, benchmarked or tested here. The
existing browser preflight still checks HTTP/HTTPS before starting Gowitness;
DNS resolution alone does not launch a browser.
