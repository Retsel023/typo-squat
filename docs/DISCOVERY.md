# Discovery and repeatable monitoring

All committed legacy scripts in this repository use Subfinder. They do not
identify a previously used Amass, Findomain, Assetfinder, or Sublist3r setup.

[OWASP Amass](https://owasp.org/projects/amass) is a plausible tool to investigate:
it combines an asset collection engine and persistent asset database. Its current
[configuration documentation](https://owasp-amass.github.io/docs/configuration/index.html)
is a better starting point than old v3 command examples. This repository does not
yet install or run Amass, and there is no measured coverage comparison for your
domains that establishes that it will return more consistent results.

[Findomain](https://github.com/Findomain/Findomain) is another possibility. Its
official documentation covers certificate transparency/API sources, importing
other enumerators' findings, and monitoring.
[Assetfinder](https://github.com/tomnomnom/assetfinder) is a smaller enumerator.
These are alternatives to evaluate, not claims of exhaustive discovery.

Subfinder's [official usage guide](https://docs.projectdiscovery.io/opensource/subfinder/usage)
documents `-all` to use all sources, API provider configuration, timeout/rate
controls, and collecting source attribution in JSONL output. The legacy command
uses only `-d` and `-silent`; missing credentials and transient source failures
can change its coverage. Current adapter stderr logs are retained for diagnosis.

For this project the durable comparison rule is independent of the enumerator:
union discoveries with saved seeds, generate permutations only for seeds without
a successful cache entry for the current generator profile, and recheck every
saved candidate. A discovery source can add coverage, but a
single empty result cannot remove yesterday's names. If DNS zone inventories are
available for domains you manage, importing them can supply names passive tools
never observed. Keep source provenance and treat the DNS verification phase as
separate from discovery.

Before adding a new engine, compare source counts over repeated runs on the same
authorized roots, capture errors and credential availability, and confirm its
current CLI/version. Do not replace a working baseline with a new tool's sample.


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
