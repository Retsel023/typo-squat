import csv
import base64
import io
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from typo_monitor.web import create_app
from typo_monitor.store import Store


class FakeStore:
    def __init__(self):
        self.projects = {}
        self.runs = {}
        self.domains = {}
        self.captures = {}
        self.schedules = []
        self.dns_settings_updates = []

    def list_projects(self):
        return [self.get_project(project_id) for project_id in self.projects]

    def get_project(self, project_id):
        project = self.projects.get(project_id)
        if project is None:
            return None
        runs = self.list_runs(project_id)
        return {**project, "last_run": runs[-1] if runs else None}

    def list_runs(self, project_id, limit=None, include_events=True):
        runs = [run for run in self.runs.values() if run["project_id"] == project_id]
        return runs[:limit] if limit else runs

    def get_run(self, run_id):
        return self.runs.get(run_id)

    def get_domains(self, project_id):
        roots = self.projects[project_id]["roots"]
        return [{"sources": [], "parking": {"status": "unknown"}, "screenshots": [], "is_seed": item["domain"] in roots, **item}
                for item in self.domains.get(project_id, [])]

    def get_domain(self, project_id, domain):
        return next((item for item in self.get_domains(project_id) if item["domain"] == domain), None)

    def get_capture(self, run_id, domain, scheme):
        return self.captures.get((run_id, domain, scheme))

    def list_captures(self, project_id, domain, limit=20):
        captures = [capture for capture in self.captures.values() if capture["project_id"] == project_id and capture["domain"] == domain]
        return sorted(captures, key=lambda capture: capture["captured_at"], reverse=True)[:limit]

    def list_run_captures(self, run_id):
        return [capture for capture in self.captures.values() if capture["run_id"] == run_id]

    def inventory(self, project_id):
        return {"seeds": sorted(set(self.projects[project_id]["roots"]) | {domain["domain"] for domain in self.get_domains(project_id) if domain["is_seed"]}),
                "candidates": [domain["domain"] for domain in self.get_domains(project_id)]}

    def set_schedule(self, project_id, interval_hours):
        self.schedules.append((project_id, interval_hours))
        project = self.projects[project_id]
        project["schedule_interval_hours"] = interval_hours
        project["schedule_next_run_at"] = "2026-10-17T12:00:00+00:00" if interval_hours else None
        return self.get_project(project_id)

    def set_dns_workers(self, project_id, workers):
        self.dns_settings_updates.append((project_id, workers))
        self.projects[project_id]["dns_workers"] = workers
        return self.get_project(project_id)

    def domain_counts(self, project_id):
        domains = self.get_domains(project_id)
        return {"total": len(domains), **{status: sum(domain.get("status") == status for domain in domains) for status in ["resolved", "pending_missing", "missing", "unknown"]}}

    def export_domains(self, project_id, *, query="", status="", seed="", hide_parked=False, include_seeds=True):
        items = [domain for domain in self.get_domains(project_id)
                 if (not query or query.lower() in domain["domain"].lower())
                 and (not status or domain.get("status") == status)
                 and (include_seeds or not domain["is_seed"])
                 and (not hide_parked or domain["parking"].get("status") != "likely_parked")
                 and (not seed or (not domain["sources"] if seed == "__unattributed__" else seed in domain["sources"]))]
        items.sort(key=lambda item: item["domain"])
        return items

    def query_domains(self, project_id, *, query="", status="", seed="", hide_parked=False, include_seeds=True, limit=100, offset=0):
        items = self.export_domains(project_id, query=query, status=status, seed=seed, hide_parked=hide_parked, include_seeds=include_seeds)
        return {"items": items[offset:offset + limit], "total": len(items)}

    def source_groups(self, project_id, *, query="", status="resolved", hide_parked=False, include_seeds=False):
        groups = {}
        for domain in self.export_domains(project_id, query=query, status=status, hide_parked=hide_parked, include_seeds=include_seeds):
            for source in domain["sources"] or ["__unattributed__"]:
                groups[source] = groups.get(source, 0) + 1
        return [{"seed": seed, "total": total} for seed, total in sorted(groups.items())]


class FakeService:
    def __init__(self):
        self.store = FakeStore()
        self.submissions = []
        self.busy = False
        self.cancellations = []
        self.interval_hours = 0
        self.resolver = SimpleNamespace(workers=24)

    def create_project(self, name, roots, *, dns_workers=None):
        project = {"id": str(uuid4()), "name": name, "roots": roots, "created_at": "2026-10-16T12:00:00+00:00", "dns_workers": dns_workers}
        self.store.projects[project["id"]] = project
        return project

    def submit_scan(self, project_id):
        if self.busy:
            raise RuntimeError("A scan is already running for this project.")
        self.submissions.append(project_id)
        run = {"id": str(uuid4()), "project_id": project_id, "status": "running",
               "started_at": "2026-10-16T12:00:00+00:00", "finished_at": None,
               "dns_workers": self.dns_status(self.store.get_project(project_id))["workers"],
               "is_baseline": False, "events": [], "counts": {}, "source_status": {}}
        self.store.runs[run["id"]] = run
        return run

    def tool_status(self):
        return {"Subfinder": {"available": False, "detail": "Optional passive discovery"}, "DNS resolver": True}

    def cancel_scan(self, run_id):
        self.cancellations.append(run_id)
        run = self.store.get_run(run_id)
        if run["status"] == "running":
            run.update(status="cancelled", finished_at="2026-10-16T12:01:00+00:00")
        return run

    def dns_status(self, project):
        inherited = project.get("dns_workers") is None
        return {"workers": getattr(self, "dns_workers", self.resolver.workers) if inherited else project["dns_workers"], "inherited": inherited}


class WebTests(unittest.TestCase):
    def setUp(self):
        self.service = FakeService()
        self.app = create_app(self.service)
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()
        self.capture_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.capture_dir.cleanup)
        self.service.data_dir = Path(self.capture_dir.name)

    def token(self):
        self.client.get("/")
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def project(self, name="Example brand"):
        return self.service.create_project(name, ["example.com"])

    def capture(self, project, domain="examp1e.com", scheme="https", relative_path=None, status="captured", run=None):
        run = run or self.service.submit_scan(project["id"])
        run["status"] = "completed"
        relative_path = relative_path or f"screenshots/{domain}-{scheme}.png"
        capture = {"run_id": run["id"], "project_id": project["id"], "domain": domain,
                   "scheme": scheme, "url": f"{scheme}://{domain}", "status": status,
                   "relative_path": relative_path, "title": "Saved website", "http_status": 200,
                   "captured_at": "2026-10-16T12:00:00+00:00", "error": None}
        self.service.store.captures[(run["id"], domain, scheme)] = capture
        if status == "captured" and not Path(relative_path).is_absolute() and ".." not in Path(relative_path).parts:
            image = self.service.data_dir / "runs" / run["id"] / relative_path
            image.parent.mkdir(parents=True, exist_ok=True)
            image.write_bytes(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII="))
        return capture

    def capture_url(self, capture):
        return f"/captures/{capture['run_id']}/{capture['domain']}/{capture['scheme']}"

    def project_links(self, response):
        class ProjectLinks(HTMLParser):
            def __init__(self):
                super().__init__()
                self.links = {}

            def handle_starttag(self, tag, attributes):
                attributes = dict(attributes)
                if tag == "a" and "project-nav-link" in attributes.get("class", "").split():
                    self.links[attributes["href"]] = attributes.get("aria-current") == "page"

        parser = ProjectLinks()
        parser.feed(response.get_data(as_text=True))
        return parser.links

    def test_empty_dashboard_and_security_headers(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Your first project starts here", response.data)
        self.assertIn(b"Subfinder is optional", response.data)
        self.assertIn(b"Not installed", response.data)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("form-action 'self'", response.headers["Content-Security-Policy"])

    def test_health_is_cheap_and_does_not_enumerate_projects(self):
        self.service.store.list_projects = lambda: self.fail("Health must not query projects")
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"status": "ok"})

    def test_create_normalizes_and_redirects_to_project(self):
        response = self.client.post("/projects", data={"csrf_token": self.token(), "name": "  Brand  ", "roots": "EXAMPLE.com\nexample.com\nexample.org # second root"})
        self.assertEqual(response.status_code, 303)
        project = next(iter(self.service.store.projects.values()))
        self.assertEqual(project["name"], "Brand")
        self.assertEqual(project["roots"], ["example.com", "example.org"])
        self.assertEqual(response.headers["Location"], f"/projects/{project['id']}")
        self.assertIn(b"Ready to establish your baseline", self.client.get(response.headers["Location"]).data)

    def test_csrf_missing_wrong_and_cross_session_tokens_rejected(self):
        other = self.app.test_client()
        token = self.token()
        for client, csrf in [(self.client, ""), (self.client, "wrong"), (other, token)]:
            response = client.post("/projects", data={"csrf_token": csrf, "name": "Brand", "roots": "example.com"})
            self.assertEqual(response.status_code, 400)
        self.assertEqual(self.service.store.projects, {})

    def test_invalid_input_preserves_escaped_form(self):
        response = self.client.post("/projects", data={"csrf_token": self.token(), "name": '<script>alert("x")</script>', "roots": "https://example.com"})
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(b"<script>alert", response.data)
        self.assertIn(b"&lt;script&gt;", response.data)
        self.assertIn(b"https://example.com", response.data)
        self.assertEqual(self.service.store.projects, {})

    def test_project_and_domain_values_are_escaped_and_filterable(self):
        project = self.project('<img src=x onerror="alert(1)">')
        self.service.store.domains[project["id"]] = [
            {"domain": "a.example.com", "status": "resolved", "records": [["TXT", "<script>evil</script>"]], "first_seen": None, "last_seen": None, "last_checked": None, "last_error": None},
            {"domain": "b.example.com", "status": "unknown", "records": [], "last_seen": None, "last_checked": None, "last_error": "<script>timeout</script>"},
        ]
        response = self.client.get(f"/projects/{project['id']}?status=&include_seeds=1&view=table")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"<img src=x", response.data)
        self.assertNotIn(b"<script>evil", response.data)
        self.assertNotIn(b"<script>timeout", response.data)
        self.assertIn(b"&lt;script&gt;evil", response.data)
        self.assertIn(b"DNS uncertain", response.data)
        filtered = self.client.get(f"/projects/{project['id']}?status=unknown&q=b.example")
        self.assertIn(b"b.example.com", filtered.data)
        self.assertNotIn(b">a.example.com<", filtered.data)
        self.assertEqual(self.client.get(f"/projects/{project['id']}?status=deleted").status_code, 400)

    def test_scan_redirect_and_conflict(self):
        project = self.project()
        token = self.token()
        response = self.client.post(f"/projects/{project['id']}/scan", data={"csrf_token": token})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.service.submissions, [project["id"]])
        page = self.client.get(response.headers["Location"])
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'data-refresh="true"', page.data)
        self.assertIn(b"running in the background", page.data)
        self.service.busy = True
        conflict = self.client.post(f"/projects/{project['id']}/scan", data={"csrf_token": token})
        self.assertEqual(conflict.status_code, 409)
        self.assertIn(b"already running", conflict.data)

    def test_baseline_and_change_record_details(self):
        project = self.project()
        run = self.service.submit_scan(project["id"])
        run.update(status="completed", is_baseline=True)
        page = self.client.get(f"/runs/{run['id']}")
        self.assertIn(b"Baseline saved. Comparisons begin next scan.", page.data)
        run.update(is_baseline=False, events=[{"domain": "a.example.com", "kind": "records_changed", "before": {"records": [["A", "192.0.2.1"]]}, "after": {"records": [["A", "192.0.2.2"]]}, "detail": "Normalized DNS records changed."}])
        page = self.client.get(f"/runs/{run['id']}")
        self.assertIn(b"DNS records changed", page.data)
        self.assertIn(b"192.0.2.1", page.data)
        self.assertIn(b"192.0.2.2", page.data)

    def test_export_protects_formula_injection_and_keeps_records(self):
        project = self.project()
        self.service.store.domains[project["id"]] = [{"domain": "example.com", "status": "unknown", "records": [["A", "192.0.2.1"]], "last_error": " =HYPERLINK(\"evil\")"}]
        response = self.client.get(f"/projects/{project['id']}/export.csv?status=&include_seeds=1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/csv")
        self.assertIn(project["id"], response.headers["Content-Disposition"])
        rows = list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))
        self.assertEqual(rows[0]["last_known_records"], "A 192.0.2.1")
        self.assertTrue(rows[0]["last_error"].startswith("'"))

    def test_default_view_only_shows_currently_resolving_typo_candidates(self):
        project = self.project()
        self.service.store.domains[project["id"]] = [
            {"domain": "example.com", "status": "resolved", "is_seed": True, "sources": ["example.com"]},
            {"domain": "examp1e.com", "status": "resolved", "sources": ["example.com"]},
            {"domain": "examplee.com", "status": "unknown", "records": [["A", "192.0.2.1"]], "sources": ["example.com"]},
            {"domain": "exxample.com", "status": "missing", "sources": ["example.com"]},
        ]
        page = self.client.get(f"/projects/{project['id']}")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'<span class="domain-name">examp1e.com</span>', page.data)
        for hidden in (b"example.com", b"examplee.com", b"exxample.com"):
            self.assertNotIn(b'<span class="domain-name">' + hidden + b'</span>', page.data)
        self.assertIn(b"Hidden from default view", page.data)
        self.assertIn(b"3 inventory entries outside this view", page.data)
        all_inventory = self.client.get(f"/projects/{project['id']}?status=&include_seeds=1")
        for domain in (b"example.com", b"examp1e.com", b"examplee.com", b"exxample.com"):
            self.assertIn(b'<span class="domain-name">' + domain + b'</span>', all_inventory.data)

    def test_source_drilldown_and_parking_filters_preserve_origin_and_evidence(self):
        project = self.project()
        self.service.store.domains[project["id"]] = [
            {"domain": "examp1e.com", "status": "resolved", "sources": ["example.com"], "parking": {"status": "not_detected"}},
            {"domain": "porta1.example.com", "status": "resolved", "sources": ["portal.example.com"], "parking": {"status": "likely_parked", "provider": "Example parking", "evidence": ["<script>untrusted evidence</script>"], "checked_at": "2026-10-16T12:00:00+00:00"}},
            {"domain": "portai.example.com", "status": "resolved", "sources": ["portal.example.com", "example.com"], "parking": {"status": "unknown"}},
            {"domain": "legacy-example.com", "status": "resolved", "sources": []},
        ]
        page = self.client.get(f"/projects/{project['id']}?view=table")
        self.assertIn(b"ORIGINAL DOMAINS", page.data)
        self.assertIn(b"portal.example.com", page.data)
        self.assertIn(b"Unattributed / legacy", page.data)
        self.assertIn(b"Likely parked", page.data)
        self.assertIn(b"&lt;script&gt;untrusted evidence", page.data)
        self.assertNotIn(b"<script>untrusted evidence", page.data)
        self.assertIn(b"No known signal", page.data)
        self.assertIn(b"no signal does not mean safe", page.data)
        drilldown = self.client.get(f"/projects/{project['id']}?seed=portal.example.com")
        self.assertIn(b'<span class="domain-name">porta1.example.com</span>', drilldown.data)
        self.assertIn(b'<span class="domain-name">portai.example.com</span>', drilldown.data)
        self.assertNotIn(b'<span class="domain-name">examp1e.com</span>', drilldown.data)
        hidden = self.client.get(f"/projects/{project['id']}?seed=portal.example.com&hide_parked=1")
        self.assertNotIn(b'<span class="domain-name">porta1.example.com</span>', hidden.data)
        self.assertIn(b'<span class="domain-name">portai.example.com</span>', hidden.data)
        legacy = self.client.get(f"/projects/{project['id']}?seed=__unattributed__")
        self.assertIn(b'<span class="domain-name">legacy-example.com</span>', legacy.data)
        self.assertNotIn(b'<span class="domain-name">examp1e.com</span>', legacy.data)
        self.assertEqual(self.client.get(f"/projects/{project['id']}?seed=../../bad").status_code, 400)

    def test_csv_exports_the_current_filtered_view_with_provenance(self):
        project = self.project()
        self.service.store.domains[project["id"]] = [
            {"domain": "examp1e.com", "status": "resolved", "sources": ["example.com"], "parking": {"status": "not_detected"}},
            {"domain": "exxample.com", "status": "resolved", "sources": ["example.com"], "parking": {"status": "likely_parked", "provider": "Example parking", "evidence": ["NS pattern"]}},
            {"domain": "unknown-example.com", "status": "unknown", "sources": ["example.com"]},
        ]
        response = self.client.get(f"/projects/{project['id']}/export.csv?seed=example.com&hide_parked=1")
        rows = list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))
        self.assertEqual([row["domain"] for row in rows], ["examp1e.com"])
        self.assertEqual(rows[0]["source_domains"], "example.com")
        self.assertEqual(rows[0]["parking_status"], "not_detected")
        all_inventory = self.client.get(f"/projects/{project['id']}/export.csv?status=&include_seeds=1")
        rows = list(csv.DictReader(io.StringIO(all_inventory.get_data(as_text=True))))
        self.assertEqual(len(rows), 3)
        parked = next(row for row in rows if row["domain"] == "exxample.com")
        self.assertEqual(parked["parking_evidence"], "NS pattern")

    def test_real_store_hides_retained_unknowns_and_filters_current_parking(self):
        with tempfile.TemporaryDirectory() as data_dir:
            store = Store(data_dir)
            self.service.store = store
            project = store.create_project("Real store integration", ["example.com"])
            domains = ["example.com", "examp1e.com", "porta1.example.com"]
            sources = {"examp1e.com": ["example.com"], "porta1.example.com": ["portal.example.com"]}
            initial = store.start_run(project["id"])
            store.finish_run(initial["id"], seeds=["example.com", "portal.example.com"], candidates=domains,
                             observations={domain: {"status": "resolved", "records": [["A", "192.0.2.1"]]} for domain in domains},
                             source_status={"dns": {"status": "ok"}}, provenance=sources)
            followup = store.start_run(project["id"])
            store.finish_run(followup["id"], seeds=[], candidates=[], provenance={},
                             observations={"example.com": {"status": "resolved", "records": [["A", "192.0.2.1"]]},
                                           "examp1e.com": {"status": "unknown", "error": "Timeout"},
                                           "porta1.example.com": {"status": "resolved", "records": [["A", "192.0.2.2"]], "parking": {"status": "likely_parked", "provider": "Example parking", "evidence": ["Known parking NS"]}}},
                             source_status={"dns": {"status": "partial"}})
            page = self.client.get(f"/projects/{project['id']}")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b'<span class="domain-name">porta1.example.com</span>', page.data)
            self.assertNotIn(b'<span class="domain-name">examp1e.com</span>', page.data)
            self.assertNotIn(b'<span class="domain-name">example.com</span>', page.data)
            filtered = self.client.get(f"/projects/{project['id']}?seed=portal.example.com&hide_parked=1")
            self.assertIn(b"No candidates match these filters.", filtered.data)
            self.assertNotIn(b'<span class="domain-name">porta1.example.com</span>', filtered.data)
            all_inventory = self.client.get(f"/projects/{project['id']}?status=&include_seeds=1&view=table")
            self.assertIn(b'<span class="domain-name">examp1e.com</span>', all_inventory.data)
            self.assertIn(b"192.0.2.1", all_inventory.data)

    def test_missing_ids_invalid_paths_and_large_forms(self):
        unknown = str(uuid4())
        for path in [f"/projects/{unknown}", f"/runs/{unknown}", "/projects/not-a-uuid", "/projects/../../etc/passwd", f"/projects/{unknown}/export.csv"]:
            self.assertEqual(self.client.get(path).status_code, 404)
        self.assertEqual(self.client.post(f"/projects/{unknown}/scan", data={"csrf_token": self.token()}).status_code, 404)
        response = self.client.post("/projects", data={"csrf_token": self.token(), "roots": "x" * 70_000, "name": "Too large"})
        self.assertEqual(response.status_code, 413)

    def test_inventory_is_paginated_and_page_inputs_are_bounded(self):
        project = self.project()
        self.service.store.domains[project["id"]] = [{"domain": f"host{i:03}.example.com", "status": "resolved", "records": [], "last_seen": None, "last_checked": None} for i in range(205)]
        first = self.client.get(f"/projects/{project['id']}")
        self.assertIn(b"host099.example.com", first.data)
        self.assertNotIn(b"host100.example.com", first.data)
        self.assertIn(b"Page 1 of 3", first.data)
        last = self.client.get(f"/projects/{project['id']}?page=99999")
        self.assertIn(b"host204.example.com", last.data)
        self.assertIn(b"Page 3 of 3", last.data)
        self.assertNotIn(b"host199.example.com", last.data)
        self.assertEqual(self.client.get(f"/projects/{project['id']}?page=invalid").status_code, 400)

    def test_demo_project_is_marked_and_scan_button_disabled(self):
        project = self.project("Simulated demo")
        run = self.service.submit_scan(project["id"])
        run.update(status="completed", source_status={"demo": {"status": "ok", "detail": "Simulated only"}})
        page = self.client.get(f"/projects/{project['id']}")
        self.assertIn(b"Simulated offline demo", page.data)
        self.assertIn(b"Demo \xc2\xb7 read only", page.data)
        self.assertIn(b'disabled', page.data)

    def test_gallery_lazy_thumbnails_and_table_toggle_preserve_filters(self):
        project = self.project()
        capture = self.capture(project)
        self.service.store.domains[project["id"]] = [{"domain": "examp1e.com", "status": "resolved", "sources": ["example.com"], "screenshots": [capture]}]
        page = self.client.get(f"/projects/{project['id']}?seed=example.com&hide_parked=1")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'aria-label="Candidate screenshot gallery"', page.data)
        self.assertIn(b'loading="lazy"', page.data)
        self.assertIn(self.capture_url(capture).encode(), page.data)
        self.assertIn(b"HTTPS", page.data)
        self.assertIn(b"HTTP", page.data)
        self.assertIn(b"Not captured yet", page.data)
        self.assertIn(b"view=table", page.data)
        self.assertIn(b"hide_parked=1", page.data)
        self.assertIn(b"seed=example.com", page.data)
        self.assertNotIn(b"<iframe", page.data)
        table = self.client.get(f"/projects/{project['id']}?view=table&seed=example.com&hide_parked=1")
        self.assertIn(b'name="view" value="table"', table.data)
        self.assertIn(b"Visual review", table.data)
        self.assertNotIn(b'aria-label="Candidate screenshot gallery"', table.data)
        self.assertEqual(self.client.get(f"/projects/{project['id']}?view=unknown").status_code, 400)

    def test_capture_route_serves_png_only_with_private_cache_and_no_outbound_fetch(self):
        project = self.project()
        capture = self.capture(project)
        response = self.client.get(self.capture_url(capture))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "image/png")
        self.assertTrue(response.data.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("private", response.headers["Cache-Control"])
        self.assertIn("immutable", response.headers["Cache-Control"])
        response.close()

    def test_capture_route_checks_metadata_run_project_domain_and_protocol(self):
        project = self.project()
        capture = self.capture(project)
        url = self.capture_url(capture)
        for key, invalid in [("project_id", str(uuid4())), ("run_id", str(uuid4())), ("domain", "other.example.com"), ("scheme", "http")]:
            original = capture[key]
            capture[key] = invalid
            self.assertEqual(self.client.get(url).status_code, 404)
            capture[key] = original
        capture["status"] = "failed"
        self.assertEqual(self.client.get(url).status_code, 404)
        capture["status"] = "captured"
        self.assertEqual(self.client.get(url.rsplit("/", 1)[0] + "/ftp").status_code, 404)
        self.assertEqual(self.client.get(f"/captures/{capture['run_id']}/invalid/https").status_code, 404)

    def test_capture_route_rejects_traversal_nonimages_and_symlinks(self):
        project = self.project()
        capture = self.capture(project)
        original_path = capture["relative_path"]
        run_dir = self.service.data_dir / "runs" / capture["run_id"]
        for invalid in ("../outside.png", "/etc/passwd.png", "screenshots/../image.png", "screenshots\\image.png"):
            capture["relative_path"] = invalid
            self.assertEqual(self.client.get(self.capture_url(capture)).status_code, 404)
        svg = run_dir / "screenshots/unsafe.svg"
        svg.write_text('<svg><script>alert("unsafe")</script></svg>')
        capture["relative_path"] = "screenshots/unsafe.svg"
        self.assertEqual(self.client.get(self.capture_url(capture)).status_code, 404)
        html = run_dir / "screenshots/unsafe.png"
        html.write_text("<html><script>alert('unsafe')</script></html>")
        capture["relative_path"] = "screenshots/unsafe.png"
        self.assertEqual(self.client.get(self.capture_url(capture)).status_code, 404)
        capture["relative_path"] = "screenshots/missing.png"
        self.assertEqual(self.client.get(self.capture_url(capture)).status_code, 404)
        link = run_dir / "screenshots/link.png"
        try:
            link.symlink_to(run_dir / original_path)
        except OSError:
            self.skipTest("Symlink creation requires privileges on this platform")
        capture["relative_path"] = "screenshots/link.png"
        self.assertEqual(self.client.get(self.capture_url(capture)).status_code, 404)

    def test_capture_route_rejects_a_symlinked_runs_directory(self):
        project = self.project()
        capture = self.capture(project)
        runs_dir = self.service.data_dir / "runs"
        saved_runs = self.service.data_dir / "original-runs"
        runs_dir.rename(saved_runs)
        try:
            runs_dir.symlink_to(saved_runs, target_is_directory=True)
        except OSError:
            self.skipTest("Symlink creation requires privileges on this platform")
        self.assertEqual(self.client.get(self.capture_url(capture)).status_code, 404)

    def test_candidate_review_escapes_titles_shows_protocol_failures_and_original_reference(self):
        project = self.project()
        capture = self.capture(project)
        capture["title"] = '<img src=x onerror="alert(1)">'
        failed = self.capture(project, scheme="http", status="failed")
        failed["error"] = "<script>capture timeout</script>"
        original = self.capture(project, domain="example.com")
        self.service.store.domains[project["id"]] = [
            {"domain": "examp1e.com", "status": "resolved", "sources": ["example.com"], "records": [["A", "192.0.2.1"]], "screenshots": [capture, failed]},
            {"domain": "example.com", "status": "resolved", "sources": [], "screenshots": [original]},
        ]
        page = self.client.get(f"/projects/{project['id']}/candidates/examp1e.com?view=table&seed=example.com")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Original website references", page.data)
        self.assertIn(b"Capture failed", page.data)
        self.assertIn(b"&lt;img src=x", page.data)
        self.assertIn(b"&lt;script&gt;capture timeout", page.data)
        self.assertNotIn(b"<img src=x", page.data)
        self.assertNotIn(b"<script>capture timeout", page.data)
        self.assertIn(b"Capture history", page.data)
        self.assertIn(b"view=table", page.data)
        self.assertIn(b"192.0.2.1", page.data)
        self.assertEqual(self.client.get(f"/projects/{project['id']}/candidates/missing-example.com").status_code, 404)
        other = self.project("Other project")
        self.assertEqual(self.client.get(f"/projects/{other['id']}/candidates/examp1e.com").status_code, 404)

    def test_latest_failed_capture_shows_previous_image_with_its_original_timestamp(self):
        project = self.project()
        old = self.capture(project)
        old["captured_at"] = "2026-10-15T09:30:00+00:00"
        latest = self.capture(project, status="failed")
        latest["previous_capture"] = old
        self.service.store.domains[project["id"]] = [{"domain": "examp1e.com", "status": "resolved", "sources": ["example.com"], "screenshots": [latest]}]
        page = self.client.get(f"/projects/{project['id']}")
        self.assertIn(b"Previous capture", page.data)
        self.assertIn(b"Latest attempt failed", page.data)
        self.assertIn(b"15 Oct 2026", page.data)
        self.assertIn(self.capture_url(old).encode(), page.data)
        self.assertNotIn(self.capture_url(latest).encode(), page.data)

    def test_exact_protocol_duplicates_collapse_only_in_gallery(self):
        project = self.project()
        previous_http = self.capture(project, scheme="http")
        https = self.capture(project)
        http = self.capture(project, scheme="http", run=self.service.store.get_run(https["run_id"]))
        https["visual"] = {"change": "unchanged", "duplicate_of": None, "duplicate_kind": None}
        http["visual"] = {"change": "changed", "duplicate_of": "https", "duplicate_kind": "exact", "previous_run_id": previous_http["run_id"]}
        self.service.store.domains[project["id"]] = [{"domain": "examp1e.com", "status": "resolved", "sources": ["example.com"], "screenshots": [http, https]}]
        gallery = self.client.get(f"/projects/{project['id']}")
        self.assertEqual(gallery.status_code, 200)
        self.assertIn("HTTP + HTTPS · identical".encode(), gallery.data)
        self.assertEqual(gallery.data.count(b'<img '), 1)
        self.assertIn(self.capture_url(https).encode(), gallery.data)
        self.assertNotIn(('src="' + self.capture_url(http) + '"').encode(), gallery.data)
        self.assertIn(b"Image unchanged", gallery.data)
        self.assertIn(b"Image changed", gallery.data)
        self.assertIn(b'class="image-protocol">HTTP</span>', gallery.data)
        self.assertIn(b'class="image-protocol">HTTPS</span>', gallery.data)
        review = self.client.get(f"/projects/{project['id']}/candidates/examp1e.com")
        self.assertIn(self.capture_url(http).encode(), review.data)
        self.assertIn(self.capture_url(https).encode(), review.data)
        self.assertEqual(review.data.count(b'<img '), 4)
        self.assertIn(b"Image changes between scans", review.data)
        self.assertIn(self.capture_url(previous_http).encode(), review.data)
        for capture in (http, https):
            with self.client.get(self.capture_url(capture)) as response:
                self.assertEqual(response.status_code, 200)

    def test_similar_and_different_run_protocol_images_are_not_labeled_identical(self):
        project = self.project()
        https = self.capture(project)
        http = self.capture(project, scheme="http", run=self.service.store.get_run(https["run_id"]))
        http["visual"] = {"change": "changed", "duplicate_of": "https", "duplicate_kind": "similar", "distance": 2}
        self.service.store.domains[project["id"]] = [{"domain": "examp1e.com", "status": "resolved", "screenshots": [http, https]}]
        gallery = self.client.get(f"/projects/{project['id']}")
        self.assertIn(b"Visually similar", gallery.data)
        self.assertNotIn("HTTP + HTTPS · identical".encode(), gallery.data)
        self.assertEqual(gallery.data.count(b'<img '), 2)
        http["visual"]["duplicate_kind"] = "exact"
        http["run_id"] = str(uuid4())
        gallery = self.client.get(f"/projects/{project['id']}")
        self.assertNotIn("HTTP + HTTPS · identical".encode(), gallery.data)
        self.assertEqual(gallery.data.count(b'<img '), 2)

    def test_local_change_badge_and_before_after_do_not_require_ai(self):
        project = self.project()
        old = self.capture(project)
        old["captured_at"] = "2026-10-15T09:30:00+00:00"
        current = self.capture(project)
        current["visual"] = {"change": "changed", "distance": 4, "previous_run_id": old["run_id"]}
        self.service.store.domains[project["id"]] = [{"domain": "examp1e.com", "status": "resolved", "screenshots": [current]}]
        gallery = self.client.get(f"/projects/{project['id']}")
        self.assertIn(b"Image changed", gallery.data)
        self.assertIn(b"Local comparison", gallery.data)
        review = self.client.get(f"/projects/{project['id']}/candidates/examp1e.com")
        self.assertIn(b"Image changes between scans", review.data)
        self.assertIn(b"Before", review.data)
        self.assertIn(b"After", review.data)
        self.assertIn(self.capture_url(old).encode(), review.data)
        self.assertIn(b"Perceptual distance: 4", review.data)
        self.assertNotIn(b"AI assessment", review.data)
        current["status"] = "failed"
        current["previous_capture"] = old
        current["visual"] = {"change": "uncertain", "error": "<script>comparison failure</script>"}
        review = self.client.get(f"/projects/{project['id']}/candidates/examp1e.com")
        self.assertIn(b"Comparison uncertain", review.data)
        self.assertIn(b"&lt;script&gt;comparison failure", review.data)
        self.assertNotIn(b"Image changes between scans", review.data)

    def test_saved_ai_assessment_is_escaped_and_distinct_from_local_comparison(self):
        project = self.project()
        capture = self.capture(project)
        capture["visual"] = {"change": "unchanged"}
        capture["analysis"] = {"provider": "External provider", "model": "<script>model</script>",
                               "summary": "<img src=x onerror=alert(1)>", "risk": "needs_review", "confidence": 0.7,
                               "reviewed_at": "2026-10-16T13:00:00+00:00"}
        self.service.store.domains[project["id"]] = [{"domain": "examp1e.com", "status": "resolved", "screenshots": [capture]}]
        page = self.client.get(f"/projects/{project['id']}/candidates/examp1e.com")
        self.assertIn(b"AI assessment", page.data)
        self.assertIn(b"Image unchanged", page.data)
        self.assertIn(b"Local comparison", page.data)
        self.assertIn(b"&lt;script&gt;model", page.data)
        self.assertIn(b"&lt;img src=x", page.data)
        self.assertNotIn(b"<img src=x", page.data)
        self.assertNotIn(b"<script>model", page.data)

    def test_automation_uses_bearer_auth_while_browser_forms_still_require_csrf(self):
        project = self.project()
        token = "test-automation-token-" + "x" * 32
        with patch.dict("os.environ", {"TYPO_MONITOR_API_TOKEN": token}):
            app = create_app(self.service)
        app.config["TESTING"] = True
        client = app.test_client()
        unauthorized = client.post("/api/scans", json={"project_id": project["id"]})
        self.assertEqual(unauthorized.status_code, 401)
        authorized = client.post("/api/scans", json={"project_id": project["id"]}, headers={"Authorization": "Bearer " + token})
        self.assertEqual(authorized.status_code, 202)
        browser = client.post("/projects", data={"name": "No CSRF", "roots": "example.org"}, headers={"Authorization": "Bearer " + token})
        self.assertEqual(browser.status_code, 400)

    def test_completed_run_shows_local_handoff_counts_and_bounded_escaped_preview(self):
        project = self.project()
        run = self.service.submit_scan(project["id"])
        run["status"] = "completed"
        items = [{"domain": f"candidate{i}.example.com", "scheme": "https", "visual_status": "changed", "previous": {"run_id": "previous"}, "references": []} for i in range(12)]
        items[0]["domain"] = "<img src=x onerror=alert(1)>"
        summary = {"total_captures": 50, "selected_pairs": 12,
                   "excluded": {"original": 2, "failed": 3, "unchanged": 20, "uncertain": 4, "duplicate": 5, "parked": 2, "reviewed": 2}}
        with patch("typo_monitor.web.review_selection", return_value={"run_id": run["id"], "items": items, "summary": summary}) as selector:
            page = self.client.get(f"/runs/{run['id']}")
        selector.assert_called_once_with(self.service.store, run["id"])
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"AI handoff preview", page.data)
        self.assertIn(b"LOCAL ONLY", page.data)
        self.assertIn(b"Selected review pairs", page.data)
        self.assertIn(b"Excluded captures", page.data)
        self.assertIn(b"38", page.data)
        self.assertIn(b"Unchanged images", page.data)
        self.assertIn(b"Already reviewed", page.data)
        self.assertIn(b"10 shown", page.data)
        self.assertIn(b"candidate9.example.com", page.data)
        self.assertNotIn(b"candidate10.example.com", page.data)
        self.assertNotIn(b"<img src=x", page.data)
        self.assertIn(b"&lt;img src=x", page.data)
        self.assertIn(b"no n8n or AI provider is called", page.data)
        self.assertNotIn(b"data:image/", page.data)

    def test_running_scan_does_not_compute_a_handoff_preview(self):
        project = self.project()
        run = self.service.submit_scan(project["id"])
        with patch("typo_monitor.web.review_selection", side_effect=AssertionError("Running scan must not build a review selection")):
            page = self.client.get(f"/runs/{run['id']}")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn(b"AI handoff preview", page.data)

    def test_new_project_link_opens_a_dedicated_form_from_any_project(self):
        project = self.project("Clazing")
        project_page = self.client.get(f"/projects/{project['id']}")
        self.assertIn(b'href="/projects/new"', project_page.data)
        self.assertNotIn(b'href="/#new-project"', project_page.data)
        form_page = self.client.get("/projects/new")
        self.assertEqual(form_page.status_code, 200)
        self.assertIn(b"Create a project", form_page.data)
        self.assertIn(b'action="/projects"', form_page.data)
        self.assertIn(b'name="csrf_token"', form_page.data)
        self.assertIn(b'href="/projects/new" aria-current="page"', form_page.data)
        self.assertEqual(self.project_links(form_page), {f"/projects/{project['id']}": False})

    def test_sidebar_lists_and_escapes_all_projects_with_current_context_highlight(self):
        first = self.project("Clazing")
        second = self.project('<script>Other client</script>')
        self.service.store.domains[first["id"]] = [{"domain": "clazlng.example", "status": "resolved"}]
        run = self.service.submit_scan(first["id"])
        pages = [self.client.get(f"/projects/{first['id']}"), self.client.get(f"/runs/{run['id']}"),
                 self.client.get(f"/projects/{first['id']}/candidates/clazlng.example")]
        expected = {f"/projects/{first['id']}": True, f"/projects/{second['id']}": False}
        for page in pages:
            self.assertEqual(page.status_code, 200)
            self.assertEqual(self.project_links(page), expected)
            self.assertIn(b"&lt;script&gt;Other client&lt;/script&gt;", page.data)
            self.assertNotIn(b"<script>Other client</script>", page.data)
        overview = self.client.get("/")
        self.assertEqual(self.project_links(overview), {key: False for key in expected})
        self.assertIn(b'href="/" aria-current="page"', overview.data)
        self.assertIn(b"Clazing", overview.data)
        self.assertIn(b"Other client", overview.data)

    def test_selecting_one_client_keeps_real_store_findings_history_and_exports_scoped(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            self.service.store = store
            clazing = store.create_project("Clazing", ["clazing.example"])
            other = store.create_project("Other client", ["other.example"])

            def finish(project, candidate, address):
                run = store.start_run(project["id"])
                return store.finish_run(run["id"], seeds=project["roots"],
                    candidates=[*project["roots"], candidate],
                    observations={domain: {"status": "resolved", "records": [["A", address]]}
                                  for domain in [*project["roots"], candidate]},
                    source_status={"dns": {"status": "ok"}}, provenance={candidate: project["roots"]})

            first = finish(clazing, "clazlng.example", "192.0.2.1")
            latest = finish(clazing, "clazlng.example", "192.0.2.2")
            unrelated = finish(other, "other-typo.example", "192.0.2.3")
            response = self.client.get(f"/projects/{clazing['id']}")
            self.assertEqual(response.status_code, 200)
            main = response.get_data(as_text=True).split('<main ', 1)[1].split('</main>', 1)[0]
            self.assertIn('<span class="domain-name">clazlng.example</span>', main)
            self.assertNotIn('<span class="domain-name">other-typo.example</span>', main)
            self.assertIn(f'/runs/{first["id"]}', main)
            self.assertIn(f'/runs/{latest["id"]}', main)
            self.assertNotIn(f'/runs/{unrelated["id"]}', main)
            self.assertIn(f'action="/projects/{clazing["id"]}/scan"', main)
            self.assertNotIn(f'action="/projects/{other["id"]}/scan"', main)
            self.assertEqual(self.project_links(response), {f'/projects/{clazing["id"]}': True, f'/projects/{other["id"]}': False})
            exported = self.client.get(f"/projects/{clazing['id']}/export.csv")
            domains = [row["domain"] for row in csv.DictReader(io.StringIO(exported.get_data(as_text=True)))]
            self.assertEqual(domains, ["clazlng.example"])
            self.assertEqual(self.client.get(f"/projects/{clazing['id']}/candidates/other-typo.example").status_code, 404)
            other_run = self.client.get(f"/runs/{unrelated['id']}")
            self.assertEqual(self.project_links(other_run), {f'/projects/{clazing["id"]}': False, f'/projects/{other["id"]}': True})
            self.assertNotIn(b"clazlng.example", other_run.data)

    def test_scan_submission_targets_the_selected_client_only(self):
        clazing = self.project("Clazing")
        other = self.project("Other client")
        token = self.token()
        response = self.client.post(f"/projects/{clazing['id']}/scan", data={"csrf_token": token})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.service.submissions, [clazing["id"]])
        self.assertEqual(self.service.store.list_runs(other["id"]), [])
        run_page = self.client.get(response.headers["Location"])
        self.assertEqual(self.project_links(run_page), {f'/projects/{clazing["id"]}': True, f'/projects/{other["id"]}': False})

    def test_stop_scan_targets_one_run_and_removes_controls_after_stopping(self):
        clazing, other = self.project("Clazing"), self.project("Other client")
        run = self.service.submit_scan(clazing["id"])
        other_run = self.service.submit_scan(other["id"])
        token = self.token()
        project_page = self.client.get(f"/projects/{clazing['id']}")
        run_page = self.client.get(f"/runs/{run['id']}")
        for page in (project_page, run_page):
            self.assertIn(f'action="/runs/{run["id"]}/cancel"'.encode(), page.data)
            self.assertNotIn(f'action="/runs/{other_run["id"]}/cancel"'.encode(), page.data)
            self.assertIn(b"Stop scan", page.data)
        response = self.client.post(f"/runs/{run['id']}/cancel", data={"csrf_token": token})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["Location"], f"/runs/{run['id']}")
        self.assertEqual(self.service.cancellations, [run["id"]])
        self.assertEqual(run["status"], "cancelled")
        self.assertEqual(other_run["status"], "running")
        stopped = self.client.get(response.headers["Location"])
        self.assertIn(b"Stopped", stopped.data)
        self.assertIn(b"Previous results were kept", stopped.data)
        self.assertIn(b"Scan stopped before comparison completed", stopped.data)
        self.assertNotIn(f'action="/runs/{run["id"]}/cancel"'.encode(), stopped.data)
        self.assertNotIn(b'data-refresh="true"', stopped.data)
        self.assertEqual(self.project_links(stopped), {f'/projects/{clazing["id"]}': True, f'/projects/{other["id"]}': False})

    def test_cancel_requires_csrf_and_handles_finished_or_missing_runs(self):
        project = self.project()
        run = self.service.submit_scan(project["id"])
        self.assertEqual(self.client.post(f"/runs/{run['id']}/cancel").status_code, 400)
        self.assertEqual(self.service.cancellations, [])
        self.assertEqual(run["status"], "running")
        token = self.token()
        run["status"] = "completed"  # The worker may finish before a stop request arrives.
        response = self.client.post(f"/runs/{run['id']}/cancel", data={"csrf_token": token})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(run["status"], "completed")
        self.assertIn(b"already finished", self.client.get(response.headers["Location"]).data)
        run["status"] = "cancelled"
        response = self.client.post(f"/runs/{run['id']}/cancel", data={"csrf_token": token})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(run["status"], "cancelled")
        self.assertEqual(self.client.post(f"/runs/{uuid4()}/cancel", data={"csrf_token": token}).status_code, 404)

    def test_project_schedule_is_validated_scoped_and_can_be_turned_off(self):
        clazing, other = self.project("Clazing"), self.project("Other client")
        page = self.client.get(f"/projects/{clazing['id']}")
        self.assertIn(b"Scan schedule", page.data)
        self.assertIn(b'value="0"', page.data)
        self.assertIn(f'action="/projects/{clazing["id"]}/schedule"'.encode(), page.data)
        token = self.token()
        response = self.client.post(f"/projects/{clazing['id']}/schedule", data={"csrf_token": token, "interval_hours": "24"})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["Location"], f"/projects/{clazing['id']}#schedule")
        self.assertEqual(self.service.store.schedules, [(clazing["id"], 24)])
        self.assertNotIn("schedule_interval_hours", self.service.store.projects[other["id"]])
        scheduled = self.client.get(response.headers["Location"])
        self.assertIn(b"Every 24 hours", scheduled.data)
        self.assertIn(b"Next due 17 Oct 2026", scheduled.data)
        self.assertIn(b"Turn off", scheduled.data)
        self.assertIn(b"Schedules run while this server is online", scheduled.data)
        self.assertIn(b"Stopping a scan leaves this schedule enabled", scheduled.data)
        response = self.client.post(f"/projects/{clazing['id']}/schedule", data={"csrf_token": token, "action": "off"})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.service.store.projects[clazing["id"]]["schedule_interval_hours"], 0)
        self.assertIsNone(self.service.store.projects[clazing["id"]]["schedule_next_run_at"])
        self.assertEqual(self.service.submissions, [])  # Editing a schedule never starts an immediate scan.

    def test_schedule_rejects_nonfinite_out_of_range_missing_csrf_and_demo(self):
        project = self.project()
        self.assertEqual(self.client.post(f"/projects/{project['id']}/schedule", data={"interval_hours": "24"}).status_code, 400)
        token = self.token()
        for value in ("", "nan", "inf", "-inf", "1e309", "-1", "0.5", "8760.1", "garbage"):
            with self.subTest(value=value):
                response = self.client.post(f"/projects/{project['id']}/schedule", data={"csrf_token": token, "interval_hours": value})
                self.assertEqual(response.status_code, 400)
        self.assertEqual(self.service.store.schedules, [])
        for value in ("1", "8760", "1.5"):
            with self.subTest(boundary=value):
                self.assertEqual(self.client.post(f"/projects/{project['id']}/schedule", data={"csrf_token": token, "interval_hours": value}).status_code, 303)
        demo = self.service.submit_scan(project["id"])
        demo.update(status="completed", source_status={"demo": {"status": "ok"}})
        previous = list(self.service.store.schedules)
        self.assertEqual(self.client.post(f"/projects/{project['id']}/schedule", data={"csrf_token": token, "interval_hours": "24"}).status_code, 409)
        self.assertEqual(self.service.store.schedules, previous)
        self.assertEqual(self.client.post(f"/projects/{uuid4()}/schedule", data={"csrf_token": token, "interval_hours": "24"}).status_code, 404)

    def test_inherited_schedule_is_visible_and_explicit_off_overrides_it(self):
        project = self.project()
        self.service.interval_hours = 24
        page = self.client.get(f"/projects/{project['id']}")
        self.assertIn(b"Following the server default", page.data.split(b'id="schedule"', 1)[1].split(b'</section>', 1)[0])
        self.assertIn(b"Every 24 hours", page.data)
        token = self.token()
        self.client.post(f"/projects/{project['id']}/schedule", data={"csrf_token": token, "action": "off"})
        page = self.client.get(f"/projects/{project['id']}")
        self.assertNotIn(b"Following the server default", page.data.split(b'id="schedule"', 1)[1].split(b'</section>', 1)[0])
        self.assertNotIn(b"Every 24 hours", page.data)
        self.assertIn(b"Start scans manually while this schedule is off", page.data)

    def test_service_schedule_status_supplies_effective_interval_and_next_due(self):
        project = self.project()
        self.service.schedule_status = lambda item: {"interval_hours": 168, "next_run_at": "2026-10-23T09:00:00+00:00", "inherited": False}
        page = self.client.get(f"/projects/{project['id']}")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Every 168 hours", page.data)
        self.assertIn(b"Next due 23 Oct 2026", page.data)

    def test_stopping_one_scan_leaves_its_project_schedule_enabled(self):
        project = self.project()
        self.service.store.set_schedule(project["id"], 24)
        run = self.service.submit_scan(project["id"])
        response = self.client.post(f"/runs/{run['id']}/cancel", data={"csrf_token": self.token()})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(run["status"], "cancelled")
        self.assertEqual(self.service.store.projects[project["id"]]["schedule_interval_hours"], 24)
        page = self.client.get(f"/projects/{project['id']}")
        self.assertIn(b"Every 24 hours", page.data)
        self.assertIn(b"Turn off", page.data)
        self.assertIn(b"Stopping a scan leaves this schedule enabled", page.data)
        self.assertNotIn(f'action="/runs/{run["id"]}/cancel"'.encode(), page.data)
        self.assertNotIn("Stopping…".encode(), page.data)

    def test_creation_forms_offer_dns_workers_and_accept_twenty_before_first_scan(self):
        for path in ("/", "/projects/new"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'name="dns_workers"', response.data)
            self.assertIn(b'placeholder="Server default (24)"', response.data)
        response = self.client.post("/projects", data={"csrf_token": self.token(), "name": "Clazing", "roots": "clazing.example", "dns_workers": "20"})
        self.assertEqual(response.status_code, 303)
        project = next(iter(self.service.store.projects.values()))
        self.assertEqual(project["dns_workers"], 20)
        self.assertIsInstance(project["dns_workers"], int)
        self.assertEqual(self.service.submissions, [])
        self.assertIn(b"20 workers", self.client.get(response.headers["Location"]).data)
        run = self.service.submit_scan(project["id"])
        self.assertEqual(run["dns_workers"], 20)
        self.assertIn(b'DNS workers for this scan</span><strong>20</strong>', self.client.get(f"/runs/{run['id']}").data)

    def test_creation_workers_blank_inherits_and_invalid_values_do_not_create_projects(self):
        token = self.token()
        for workers in ("0", "129", "20.0", "-1", "1e2", "nan", "inf", "garbage", "２０"):
            with self.subTest(workers=workers):
                response = self.client.post("/projects", data={"csrf_token": token, "name": "Clazing", "roots": "clazing.example", "dns_workers": workers})
                self.assertEqual(response.status_code, 400)
        self.assertEqual(self.service.store.projects, {})
        for workers in ("", "1", "128"):
            with self.subTest(valid=workers):
                response = self.client.post("/projects", data={"csrf_token": token, "name": "Clazing", "roots": "clazing.example", "dns_workers": workers})
                self.assertEqual(response.status_code, 303)
        values = [project["dns_workers"] for project in self.service.store.projects.values()]
        self.assertEqual(values, [None, 1, 128])

    def test_dns_settings_change_only_the_selected_client_and_future_queued_scans(self):
        clazing, other = self.project("Clazing"), self.project("Other client")
        active = self.service.submit_scan(clazing["id"])
        self.assertEqual(active["dns_workers"], 24)
        response = self.client.post(f"/projects/{clazing['id']}/dns-settings", data={"csrf_token": self.token(), "dns_workers": "20"})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["Location"], f"/projects/{clazing['id']}#dns-settings")
        self.assertEqual(self.service.store.dns_settings_updates, [(clazing["id"], 20)])
        self.assertIsNone(self.service.store.projects[other["id"]]["dns_workers"])
        self.assertEqual(active["dns_workers"], 24)
        page = self.client.get(f"/projects/{clazing['id']}")
        self.assertIn(b"20 workers", page.data)
        self.assertIn(b"This active scan uses 24 workers", page.data)
        self.assertIn(b"Queued and running scans keep their original setting", page.data)
        self.assertEqual(self.service.submissions, [clazing["id"]])
        active["status"] = "completed"
        next_run = self.service.submit_scan(clazing["id"])
        self.assertEqual(next_run["dns_workers"], 20)
        self.assertEqual(active["dns_workers"], 24)

    def test_dns_settings_reset_to_server_default_and_respect_csrf_validation_and_demo(self):
        project = self.project()
        route = f"/projects/{project['id']}/dns-settings"
        self.assertEqual(self.client.post(route, data={"dns_workers": "20"}).status_code, 400)
        token = self.token()
        for workers in ("0", "129", "1.5", "-1", "1e1", "nan", "inf", "invalid"):
            with self.subTest(workers=workers):
                self.assertEqual(self.client.post(route, data={"csrf_token": token, "dns_workers": workers}).status_code, 400)
        self.assertEqual(self.service.store.dns_settings_updates, [])
        self.assertEqual(self.client.post(route, data={"csrf_token": token, "dns_workers": "20"}).status_code, 303)
        self.assertEqual(self.client.post(route, data={"csrf_token": token, "dns_workers": ""}).status_code, 303)
        self.assertIsNone(self.service.store.projects[project["id"]]["dns_workers"])
        page = self.client.get(f"/projects/{project['id']}")
        self.assertIn(b"24 workers", page.data)
        self.assertIn(b'placeholder="Server default (24)"', page.data)
        run = self.service.submit_scan(project["id"])
        run.update(status="completed", source_status={"demo": {"status": "ok"}})
        previous = list(self.service.store.dns_settings_updates)
        self.assertEqual(self.client.post(route, data={"csrf_token": token, "dns_workers": "20"}).status_code, 409)
        self.assertEqual(self.service.store.dns_settings_updates, previous)
        self.assertEqual(self.client.post(f"/projects/{uuid4()}/dns-settings", data={"csrf_token": token, "dns_workers": "20"}).status_code, 404)

    def test_dns_worker_context_uses_server_default_and_run_history_never_invents_it(self):
        self.service.resolver.workers = 32
        project = self.project()
        self.assertIn(b'placeholder="Server default (32)"', self.client.get("/projects/new").data)
        self.assertIn(b"32 workers", self.client.get(f"/projects/{project['id']}").data)
        run = self.service.submit_scan(project["id"])
        self.service.store.set_dns_workers(project["id"], 20)
        run["status"] = "completed"
        page = self.client.get(f"/runs/{run['id']}")
        self.assertIn(b'DNS workers for this scan</span><strong>32</strong>', page.data)
        run["dns_workers"] = None  # Historical captures predate the setting.
        page = self.client.get(f"/runs/{run['id']}")
        self.assertIn(b'DNS workers for this scan</span><strong>Not recorded</strong>', page.data)

    def test_server_default_placeholder_does_not_follow_active_run_worker_override(self):
        self.service.dns_workers = 24
        self.service.resolver.workers = 20  # The single worker is executing a client override.
        for path in ("/", "/projects/new"):
            page = self.client.get(path)
            self.assertIn(b'placeholder="Server default (24)"', page.data)
            self.assertNotIn(b'placeholder="Server default (20)"', page.data)


if __name__ == "__main__":
    unittest.main()
