"""An explicit offline demonstration, never mixed into real projects."""

from datetime import datetime, timezone
from pathlib import Path
import shutil


def _demo_captures(service, run, observations, *, changed=False):
    """Use labeled, locally captured fixtures rather than inventing real evidence."""
    from .visuals import annotate_captures
    workdir = service.data_dir / "runs" / run["id"]
    target = workdir / "screenshots"
    target.mkdir(parents=True)
    assets = Path(__file__).parent / "static" / "demo"
    for name in ("reference", "imitation", "parked"):
        shutil.copyfile(assets / f"{name}.png", target / f"demo-{name}.png")
    captures = {}
    for domain, observation in observations.items():
        if observation["status"] != "resolved":
            continue
        parked = observation.get("parking", {}).get("status") == "likely_parked"
        image = "parked" if parked else "reference"
        if changed and (domain == "login.examp1e.com" or "-008." in domain or "-009." in domain):
            image = "imitation"
        captures[domain] = []
        for scheme in ("http", "https"):
            # One explicit HTTP failure demonstrates the dated previous image.
            failed = changed and scheme == "http" and "-010." in domain
            captures[domain].append({"scheme": scheme, "url": f"{scheme}://{domain}",
                "status": "failed" if failed else "captured", "relative_path": None if failed else f"screenshots/demo-{image}.png",
                "title": "SIMULATED local fixture · " + image, "http_status": None if failed else 200,
                "error": "Simulated HTTP capture timeout" if failed else None,
                "captured_at": datetime.now(timezone.utc).isoformat()})
    return annotate_captures(captures, workdir=workdir, data_dir=service.data_dir,
        previous=lambda domain, scheme: service.store.latest_successful_capture(run["project_id"], domain, scheme))


def seed_demo(service):
    project = service.create_project("Simulated demo " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), ["example.com"])
    sources = {"demo": {"status": "ok", "detail": "SIMULATED offline fixture. No DNS queries or discovery were performed."}}
    seeds = ["example.com", "api.example.com", "login.example.com", "mail.example.com", "portal.example.com"]
    provenance, observations = {}, {}
    not_detected = {"status": "not_detected", "provider": None, "evidence": ["Simulated: no recognized parking DNS indicators."]}
    for source_index, seed in enumerate(seeds):
        provenance[seed] = [seed]
        observations[seed] = {"status": "resolved", "records": [["A", f"192.0.2.{source_index + 10}"]], "parking": not_detected}
        prefix = "" if seed == "example.com" else seed.split(".")[0] + "."
        # Hundreds of synthetic permutations illustrate the scale of each seed
        # without querying anyone's domains or claiming these are real findings.
        for number in range(125):
            candidate = f"{prefix}examp1e-{number:03d}.com"
            provenance[candidate] = [seed]
            if number < 44:
                parking = not_detected
                if number < 8:
                    parking = {"status": "likely_parked", "provider": "Afternic" if number % 2 else "Sedo",
                               "evidence": ["SIMULATED parking-specific DNS nameservers; not a real lookup."]}
                observations[candidate] = {"status": "resolved", "records": [["A", f"192.0.2.{50 + number}"]], "parking": parking}
            else:
                observations[candidate] = {"status": "nxdomain", "records": []}
    provenance.update({"examp1e.com": ["example.com"], "examplle.com": ["example.com", "portal.example.com"],
                       "login.examp1e.com": ["login.example.com"]})
    observations.update({"examp1e.com": {"status": "resolved", "records": [["A", "192.0.2.20"]], "parking": not_detected},
                         "examplle.com": {"status": "nxdomain", "records": []},
                         "login.examp1e.com": {"status": "resolved", "records": [["A", "192.0.2.40"]], "parking": not_detected}})
    candidates = sorted(observations)
    baseline = service.store.start_run(project["id"])
    first_images = _demo_captures(service, baseline, observations)
    service.store.finish_run(baseline["id"], seeds=seeds, candidates=candidates, observations=observations,
                             source_status=sources, provenance=provenance, screenshots=first_images)
    second = service.store.start_run(project["id"])
    observations["examp1e.com"] = {"status": "unknown", "records": [], "error": "Simulated DNS timeout; previous answer retained"}
    observations["examplle.com"] = {"status": "resolved", "records": [["A", "192.0.2.30"]], "parking": not_detected}
    observations["login.examp1e.com"] = {"status": "resolved", "records": [["A", "192.0.2.41"]], "parking": not_detected}
    next_images = _demo_captures(service, second, observations, changed=True)
    service.store.finish_run(second["id"], seeds=["example.com"], candidates=candidates, observations=observations,
                             source_status=sources, provenance=provenance, screenshots=next_images)
    return project
