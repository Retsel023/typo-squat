"""Carry forward old search inventory without inventing historical certainty."""

from pathlib import Path
from .domains import normalize_domain


def import_inventory(service, name, roots, output_dir):
    output_dir = Path(output_dir).resolve()
    if not output_dir.is_dir():
        raise ValueError("Legacy output directory does not exist.")
    seeds, candidates, files, invalid = set(roots), set(roots), 0, 0
    patterns = {"combined_domains.txt": seeds, "discovered_subdomains.txt": seeds,
                "deduplicated_domains.txt": candidates, "checked_domains.txt": candidates}
    for filename, target in patterns.items():
        for file in output_dir.rglob(filename):
            if not file.is_file():
                continue
            files += 1
            for line in file.read_text(encoding="utf-8-sig", errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    target.add(normalize_domain(line.strip()))
                except ValueError:
                    invalid += 1
    if not files:
        raise ValueError("No legacy combined_domains, discovered_subdomains, deduplicated_domains or checked_domains files found.")
    candidates.update(seeds)
    if len(candidates) > service.max_candidates:
        raise ValueError("Legacy inventory exceeds --max-candidates; increase the limit to import it without truncation.")
    project = service.create_project(name, roots)
    run = service.store.start_run(project["id"])
    service.store.finish_run(run["id"], seeds=sorted(seeds), candidates=sorted(candidates), observations={},
        source_status={"legacy_import": {"status": "partial", "detail": "Inventory imported; no trusted historical DNS baseline. Run a fresh scan.",
                       "files": files, "invalid_names_excluded": invalid}})
    return project
