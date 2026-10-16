# Discovery and repeatable monitoring

[OWASP Amass](https://owasp.org/projects/amass) is the default discovery engine
for new scans. Subfinder remains available through explicit selection. There is
no automatic fallback: if the selected executable is missing, fails or exceeds
its time budget, source health records the gap while roots and saved inventory
continue through the remaining scan stages.

Global options go before the CLI command:

```sh
python -m typo_monitor --discovery-engine amass --amass-path /path/to/amass --discovery-timeout 600 serve
python -m typo_monitor --amass-config /path/to/amass-v4-config.yaml serve
python -m typo_monitor --discovery-engine subfinder --discovery-timeout 600 serve
python -m typo_monitor --no-discovery serve
```

`--discovery-timeout` is the application's wall-clock budget **in seconds per
root**, defaulting to 600. It is separate from upstream tools' timeout flags,
whose units and behavior differ. `--no-discovery` is an intentional skip that
keeps known seeds. Both Compose profiles pass `TYPO_DISCOVERY_ENGINE` (default
`amass`) and `TYPO_DISCOVERY_TIMEOUT` (default `600`) into the application. A
native runner accepts the same CLI options before its command.

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
health and the time budget. Neither engine guarantees exhaustive enumeration,
and this repository has no measured comparison establishing more consistent
coverage for your domains. Subfinder's
[official usage guide](https://docs.projectdiscovery.io/opensource/subfinder/usage)
describes additional source selection and provider configuration; selecting
Subfinder here does not automatically enable all providers or supply credentials.

Each Amass root attempt preserves `amass-N.txt`, `amass-N.stdout.log`,
`amass-N.stderr.log`, `amass-N.engine.log` and its `amass-db-N/` working data under
`data/runs/RUN_UUID/`, together with source health. `amass-version.log` records
the CLI compatibility check. Explicit Subfinder runs
retain `subfinder-N.txt` and `subfinder-N.stderr.log`. Old runs remain historical
Subfinder runs with their original artifacts; an upgrade does not relabel them
as Amass or invent missing discovery results.

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
