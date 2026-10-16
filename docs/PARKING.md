# Optional parking hints

The parking filter uses DNS evidence to identify domains that likely use a known parking or domain-sales service. It annotates observations; it does not remove candidates, alter DNS record baselines, or change DNS change events. A failed parking lookup produces `unknown` without making a successful DNS observation fail. Users can keep these domains visible.

Only observations whose current DNS status is `resolved` are examined. The classifier queries NS for the exact candidate and accepts only an answer owned by that same name. It does not look up parent-zone nameservers or use authority records to classify a live child. Mixed parking and unrelated nameservers produce `unknown`; conflicting parking and unrelated CNAME evidence does too. Direct CNAME evidence comes from records already attached to the queried candidate.

Provider indicators verified on 16 October 2026:

| Provider | Accepted DNS evidence | Official source |
| --- | --- | --- |
| Afternic | Exact NS `ns1.afternic.com`, `ns2.afternic.com` | [Afternic parking setup](https://www.afternic.com/domain-parking) |
| Sedo | Exact NS `ns1.sedoparking.com`, `ns2.sedoparking.com` | [Sedo parking setup](https://sedo.com/de/domains-parken/) |
| GoDaddy CashParking | Exact NS `ns01.cashparking.com`, `ns02.cashparking.com` | [GoDaddy CashParking](https://www.godaddy.com/en-uk/domains/cashparking) |
| ParkingCrew | Exact NS `ns1.parkingcrew.net`, `ns2.parkingcrew.net`; direct CNAME with one account label before `.parkingcrew.net` | [Nameserver setup](https://www.parkingcrew.com/faq.php?detail=83&mode=detail), [custom CNAME setup](https://www.parkingcrew.com/faq.php?detail=82&mode=detail) |

Names and suffix boundaries must match exactly, ignoring case and a final dot. Generic GoDaddy `domaincontrol.com` nameservers, IP blocks, broad CDN domains, registrar identity, and provider names inside unrelated suffixes are not indicators. Lookup results are reused only within one enrichment call, then discarded so a later scan can detect changed parking evidence.

This is a limited heuristic, not proof that a domain is for sale, inactive, benign, or malicious. DNS cannot confirm the page currently served, distinguish every custom parking configuration, or identify all parking providers. `not_detected` means none of these narrow rules matched. There is no HTTP probing or page-content detection in this version.
