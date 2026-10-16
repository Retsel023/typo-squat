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
union discoveries with saved seeds, generate permutations from all saved seeds,
and recheck every saved candidate. A discovery source can add coverage, but a
single empty result cannot remove yesterday's names. If DNS zone inventories are
available for domains you manage, importing them can supply names passive tools
never observed. Keep source provenance and treat the DNS verification phase as
separate from discovery.

Before adding a new engine, compare source counts over repeated runs on the same
authorized roots, capture errors and credential availability, and confirm its
current CLI/version. Do not replace a working baseline with a new tool's sample.
