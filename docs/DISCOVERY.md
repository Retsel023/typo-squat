# Discovery and repeatable monitoring

The default `combined` mode runs [OWASP Amass](https://owasp.org/projects/amass),
[Subfinder](https://github.com/projectdiscovery/subfinder) and
[Assetfinder](https://github.com/tomnomnom/assetfinder) concurrently. Each engine
has its own output directory and deadline. Results are normalized, restricted
to the project's roots, deduplicated, then combined with saved seeds. Generation
receives that union once rather than running separately for every tool.

Per-engine status stays visible even when another engine succeeds. A timeout,
nonzero exit or unavailable executable does not discard other engines' valid
results; complete valid lines from partial output are retained too. If every
engine is unavailable or fails, the scan still checks roots and retained
inventory. Selecting a single engine never silently substitutes another tool.
Stop scan signals every running discovery process group and waits for cleanup.

## Choosing whether to enumerate

The project page's **Subdomains** selector applies to the next manual scan:

- **Enumerate again** runs the configured discovery engines, merges their names
  with saved seeds, and generates only seeds missing from the current generation
  cache. All saved and newly generated candidates receive fresh DNS checks.
- **Use saved inventory** skips every enumerator and AIL generation, including
  generation-profile checks. It sends the saved candidate inventory and seeds
  straight to fresh DNS checks. Negative/uncertain candidates are included again;
  this mode does not reuse old DNS answers. Normal website checks, screenshots
  and local comparisons still follow for eligible results.

Saved inventory must already exist. An attempt that failed or was cancelled
before accepting candidates does not establish a cache. Runs completed with
gaps can still have saved candidates even when their DNS observations were
uncertain. Reusing those names does not repair the DNS failure that produced
the uncertainty; the next scan makes fresh requests.

**Scan schedules** offers independent **Full enumeration** and **Saved inventory**
intervals. For example, use 720 hours (30 days) for enumeration and 168 hours
(weekly) for saved-inventory DNS/web checks. When both are due, one full scan covers
both; cached checks do not postpone enumeration. Cached scheduling waits for an
initial saved candidate inventory. Existing single schedules remain effective
until you save the new form.

**Default for manual scans** persists the manual selector's initial choice, even
with both schedules off. Each automatic cadence chooses its own mode. Each queued
run snapshots its mode and shows it in run details; changing defaults does not
alter queued or running scans. Historical runs without a mode remain unrecorded.

The CLI accepts a per-scan override after the `scan` command:

```sh
python -m typo_monitor --data-dir ./data scan --project PROJECT_UUID --discovery-mode cached
python -m typo_monitor --data-dir ./data scan --project PROJECT_UUID --discovery-mode enumerate
```

Omitting it uses the project's saved default. Server-wide `--no-discovery`
continues to disable enumerators while allowing generation from known seeds;
it is distinct from `cached`, which skips both operations. To pick up new
subdomains or a changed generation profile, choose enumeration again. The
configured candidate limit still applies to cached runs.

## Engine configuration

Global options go before the CLI command:

```sh
python -m typo_monitor --discovery-engine combined --discovery-timeout 600 serve
python -m typo_monitor --discovery-engine amass --amass-path /path/to/amass --discovery-timeout 600 serve
python -m typo_monitor --amass-config /path/to/amass-v4-config.yaml serve
python -m typo_monitor --discovery-engine subfinder --discovery-timeout 600 serve
python -m typo_monitor --discovery-engine assetfinder --assetfinder-path /path/to/assetfinder serve
python -m typo_monitor --no-discovery serve
```

`--discovery-timeout` is the application's wall-clock budget **in seconds per
tool, per root**, defaulting to 600. Engines run concurrently, but each engine
processes its roots sequentially. Discovery waits for all selected engines to
finish or hit their deadline before generating candidates. Running tools in
parallel can improve coverage without adding all three runtimes together; it
does not guarantee faster discovery than the slowest selected engine.
The budget is separate from upstream tools' timeout flags,
whose units and behavior differ. `--no-discovery` is an intentional skip that
keeps known seeds. Both Compose profiles pass `TYPO_DISCOVERY_ENGINE` (default
`combined`) and `TYPO_DISCOVERY_TIMEOUT` (default `600`) into the application. A
native runner accepts the same CLI options before its command.

Binary overrides are `--amass-path`, `--subfinder-path` and `--assetfinder-path`.
Combined mode enables Subfinder's `-all`; explicitly selecting Subfinder alone
retains its normal provider selection. The
[official Subfinder usage guide](https://docs.projectdiscovery.io/opensource/subfinder/usage)
documents source selection and provider credentials. Enabling `-all` does not
supply API keys or bypass provider limits.

Assetfinder uses `--subs-only ROOT` and the image pins upstream's **v0.1.1
prerelease** at
[`4e95d8701aae8cff1c27af2626eb22ba110ad583`](https://github.com/tomnomnom/assetfinder/tree/4e95d8701aae8cff1c27af2626eb22ba110ad583).
The adapter validates the hostname boundary itself; upstream's suffix check can
also emit related names outside a root. Assetfinder has no version flag, so
native paths use the v0.1.1 CLI contract without claiming runtime version verification.
Its [upstream implementation](https://github.com/tomnomnom/assetfinder/blob/4e95d8701aae8cff1c27af2626eb22ba110ad583/main.go)
suppresses individual provider errors. Successful process completion therefore
does not prove every provider succeeded, and source health states that limit.
Optional credentials are inherited through `FB_APP_ID` and `FB_APP_SECRET`,
`VT_API_KEY`, and `SPYSE_API_TOKEN`; provider availability is not guaranteed.
The monitor does not create or print these credentials. Docker users must pass
needed environment variables explicitly; keep secret values outside the repository.

The image pins [Amass **v4.2.0**](https://github.com/owasp-amass/amass/releases/tag/v4.2.0)
in [`monitor/Dockerfile`](../monitor/Dockerfile). This is an intentional
compatibility pin, **not the latest Amass release**. Its enumeration command
runs within the process lifecycle controlled by this application. Amass v5.1.1
uses a separate engine and can
[launch it as a detached process](https://github.com/owasp-amass/amass/blob/v5.1.1/cmd/amass/process_unix.go);
that lifecycle and its engine service need a different integration. Native
installations must supply **v4.2.0** too. Unsupported versions, including v5,
are rejected with a visible version diagnostic rather than silently switching
tools. Docker users do not need to install Amass on the host.

The adapter uses the
[v4.2.0 enumeration CLI](https://github.com/owasp-amass/amass/blob/v4.2.0/cmd/amass/enum.go)
with `-d ROOT -nocolor -dir RUN/amass-db-N -o RUN/amass-N.txt
-log RUN/amass-N.engine.log`. `N` identifies the root within the run. Amass's
`-o` file contains typed assets and relationships; it is **not a plain domain
list**. Only `(FQDN)` endpoints within that root's scope become discovered
seeds. IP addresses, unrelated names and bare text are excluded. The raw graph
output is retained for diagnosis; its DNS relationships do not replace the
application's fresh A, AAAA and CNAME observations. Amass can make its own DNS
queries during discovery; selecting its default discovery mode does not mean
the tool makes no DNS requests.

The service repeats hostname normalization and root-scope checks before any
discovery result reaches generation, independently of each engine's parser.
`discovery-hostnames.txt` lists the filtered, deduplicated discovery names and
appears in the run's tool output. It is not a list of currently resolving
domains; those are established by the subsequent fresh DNS checks. Raw Amass
graph output is explicitly labelled as diagnostic context. IPv4 and IPv6
addresses remain valid values in freshly verified A and AAAA records, but
cannot become domain seeds. Generated typo candidates intentionally differ
from the client's roots and are checked as separate hostnames.

`--amass-config PATH` optionally supplies a provider-only v4 YAML configuration;
`TYPO_AMASS_CONFIG` is its environment equivalent and is passed by both Compose
profiles. Only this shape is accepted:

```yaml
options:
  datasources: /private/amass-datasources.yaml
```

Relative credential paths resolve against this configuration file. The separate
credential file is read by Amass; the monitor does not copy its contents into
run artifacts or logs. Scope, graph database, scan mode and other overrides are
rejected. Each root receives an explicit private effective config and isolated
graph directory, including when no provider config is supplied; an unrelated
global Amass config cannot change the run's scope or database. Provider
credentials are not bundled. Docker paths must exist inside the container,
supplied through a read-only mount if needed. Keep credential files outside
the repository.

Discovery depends on available data sources, credentials, external service
health and the time budget. The tools overlap and can report different names;
their union can add coverage, but none guarantees exhaustive enumeration.
This repository has no measured comparison establishing more consistent
coverage for your domains. Credentials are not bundled and upstream provider
availability can change.

Combined runs retain their files under `data/runs/RUN_UUID/discovery/ENGINE/`.
`discovery.json` in the run folder records the roots, per-engine status and a
hostname-to-engine provenance map. A hostname reported by three tools is one
seed with three source entries, not three generation jobs. Successful output
from an engine that later times out keeps that engine's partial status.

Each Amass root attempt preserves `amass-N.txt`, `amass-N.stdout.log`,
`amass-N.stderr.log`, `amass-N.engine.log` and its `amass-db-N/` working data under
its engine folder, together with source health. `amass-version.log` records
the CLI compatibility check. Subfinder retains `subfinder-N.txt` and
`subfinder-N.stderr.log`; Assetfinder retains `assetfinder-N.txt` and
`assetfinder-N.stderr.log`. Single-engine runs put their files directly in
`data/runs/RUN_UUID/`. Old runs retain their original engine metadata and
artifacts; upgrades do not relabel history or invent missing discovery results.

For this project the durable comparison rule is independent of the enumerator:
union discoveries with saved seeds, generate permutations only for seeds without
a successful cache entry for the current generator profile, and recheck every
saved candidate. A discovery source can add coverage, but a
single empty result cannot remove yesterday's names. If DNS zone inventories are
available for domains you manage, importing them can supply names passive tools
never observed. Keep source provenance and treat the DNS verification phase as
separate from discovery.

When evaluating coverage, compare repeated runs on the same roots, record
errors and credential availability, and keep the DNS resolver view consistent.
Changing discovery engine does not replace an existing DNS baseline or reset
the generation cache: newly discovered seeds can add candidates, while saved
names remain monitored.

Discovery still finishes before candidate generation. Later stages can overlap:
MassDNS emits a provisional positive domain only after its A, AAAA and CNAME
questions have all completed and the result is validated. Bounded HTTP/HTTPS
checks then feed responsive URLs to a single Gowitness process through standard
input while DNS continues. A full queue defers a name until the final pass rather
than blocking DNS or dropping it. Only final resolving DNS results can have
captures accepted, and accepted inventory still publishes once at run completion.
Cancellation never publishes unfinished work. The dnspython backend retains the
DNS-first path.


## Incremental permutation generation

Discovery, permutation generation and DNS checking have different jobs. A newly
discovered subdomain becomes a retained seed. AIL runs for that seed once; later
scans reuse its saved candidate inventory while DNS checks still revisit every
known candidate. A temporary discovery omission neither deletes the seed nor
forces its permutations to be regenerated.

The cache is persisted in SQLite per project, normalized seed and generator
fingerprint. The fingerprint covers AIL's package version and algorithm mode,
its generation flags, tldextract and inflect versions, the actual bundled public
suffix snapshot, the active AIL word/TLD data files, and an implementation epoch
for adapter/normalization changes. A generator-profile change regenerates each
retained seed under the new profile. Resolver settings, screenshot options and
transient DNS observations are separate from these permutation inputs.

The built-in adapter uses AIL 2.7.6's `runAll`, unlimited output and retained
originals. In this release `runAll` explicitly skips `addDynamicDns`; its
`all_homoglyph` argument is not forwarded to the homoglyph function. The active
bundled AIL files are `etc/common-misspellings.json`, `etc/homophones.txt` and
`etc/tlds-alpha-by-domain.txt`. Both extraction and the `wrongTld`/`wrongSld`
algorithms depend on tldextract's `.tld_set_snapshot`; those algorithms also read
its private-suffix section. No suffix-list download is needed during generation.

Successful generation markers are committed atomically with accepted run
inventory and provenance. Failed or interrupted runs cannot mark unfinished
seeds as generated or replace accepted observations. Older candidate/provenance
rows remain when a newer generator produces fewer names. Adapters without a
verified cache signature continue to generate each scan.

Existing databases have no trusted generation markers. The first accepted scan
after this upgrade regenerates all retained seeds once, then subsequent scans
skip unchanged seeds. An import likewise starts without trusted markers. Missing
or unreadable fingerprint inputs must not be treated as a matching cache entry;
a failure remains visible and does not erase the previous inventory.
