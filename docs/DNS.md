# Bulk DNS checks

The default pipeline uses Amass to discover subdomains, AIL to generate typo
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
concurrency.

The image pins [MassDNS v1.1.0](https://github.com/blechschmidt/massdns/releases/tag/v1.1.0)
at commit `ca8114164361f6a296399d8160bb07d55bdc4843`. Its
[upstream JSON format and flags](https://github.com/blechschmidt/massdns/blob/v1.1.0/src/main.c)
are used directly, with explicit resolver addresses, bounded retries, response
source verification and no success-only output filter. The Docker build applies
the repository's small JSON completeness patch. It preserves the original DNS
section counts, parsing completeness and raw DNS wire bytes. Python strictly
decodes those bytes before accepting records; it does not trust the tool's
rendering of record data. Native MassDNS
installations need that same patch; an unmodified binary is not silently used
with weaker validation. The dnspython backend remains an explicit alternative.

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

The backend uses the same pinned recursive resolver addresses and query types
as the Python implementation, with their declared preference order supplied
through MassDNS extended input. Keep resolvers consistent and use servers with
the same DNS view. Changing resolver addresses still requires a new project
baseline; changing discovery engine never removes saved candidates.

## Settings and output

Global options precede the command:

```sh
python -m typo_monitor --dns-backend massdns --workers 20 serve
python -m typo_monitor --massdns-path /path/to/massdns serve
python -m typo_monitor --dns-backend dnspython --workers 20 serve
```

`TYPO_DNS_BACKEND` selects the backend and is passed by both Compose profiles.
Missing MassDNS does not silently select Python. Native runs need the external
binary; Docker builds include it. The Python option uses domain worker threads
for its requests and the same observation/comparison contract.

`--dns-timeout` defaults to 4 seconds and supplies the query retry budget;
MassDNS derives a retry interval for its bounded attempts. `--massdns-timeout`
defaults to 3600 seconds for the entire bulk job. The Stop button terminates the
external process group and prevents unfinished observations being published.

Raw output is retained under `data/runs/RUN_UUID/massdns.jsonl` with diagnostics
in `massdns.stderr.log`. The input and resolver files remain per-run artifacts
but are excluded from the live-output viewer. The viewer shows bounded tails;
the observation parser reads complete records, independently of that display.

These backend changes have not been built, benchmarked or tested here. The
existing browser preflight still checks HTTP/HTTPS before starting Gowitness;
DNS resolution alone does not launch a browser.
