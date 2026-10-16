"""Linux/server entry point; no shell scripts, root access or cron required."""

import argparse
import json
import logging
import os
from pathlib import Path
import signal
import sys

from .domains import parse_domains
from .service import MonitorService


def _stop_server(_signum, _frame):
    raise KeyboardInterrupt


def parser():
    p = argparse.ArgumentParser(description="Persistent typo-domain monitoring")
    p.add_argument("--data-dir", type=Path, default=Path(__file__).resolve().parent.parent / "data")
    p.add_argument("--no-discovery", action="store_true", help="Explicitly skip Subfinder, retaining known seeds")
    p.add_argument("--resolver", action="append", help="Recursive DNS server IP; repeat for multiple servers")
    p.add_argument("--workers", type=int, default=os.environ.get("TYPO_DNS_WORKERS", "24"),
                   help="Default parallel DNS workers, 1–128 (TYPO_DNS_WORKERS, otherwise 24); client settings override")
    p.add_argument("--dns-timeout", type=float, default=4)
    p.add_argument("--max-candidates", type=int, default=250_000)
    p.add_argument("--no-screenshots", action="store_true", help="Explicitly skip browser captures; DNS monitoring continues")
    p.add_argument("--gowitness-path", help="Path to Gowitness 3.2.2")
    p.add_argument("--chrome-path", help="Path to Chrome/Chromium for captures")
    p.add_argument("--capture-workers", type=int, default=4, help="Concurrent browser captures")
    p.add_argument("--web-timeout", type=float, default=3,
                   help="HTTP/HTTPS response check timeout before browser captures, in seconds")
    p.add_argument("--capture-timeout", type=float, default=900, help="Total capture stage deadline in seconds")
    p.add_argument("--capture-driver", choices=["gorod", "chromedp"], default="gorod")
    commands = p.add_subparsers(dest="command", required=True)
    server = commands.add_parser("serve", help="Run production WSGI server and background scan worker")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=5000)
    server.add_argument("--interval-hours", type=float, default=0, help="Scan each project at this cadence; 0 means manual")
    scan = commands.add_parser("scan", help="Run one scan; reuse a named project with the same roots")
    target = scan.add_mutually_exclusive_group(required=True)
    target.add_argument("--project", help="Existing project UUID")
    target.add_argument("--name", help="Create/reuse a named project (also requires --domains)")
    scan.add_argument("--domains", type=Path, help="UTF-8 domain list, one per line")
    commands.add_parser("projects", help="List project IDs and roots")
    commands.add_parser("doctor", help="Show installed scanner dependencies without making network requests")
    demo = commands.add_parser("demo", help="Create explicitly simulated observations without network requests")
    demo.add_argument("--report-output", type=Path, help="Also save a local HTML/JSON handoff preview")
    preview = commands.add_parser("handoff-preview", help="Measure a local review batch; never contact n8n or AI")
    preview_target = preview.add_mutually_exclusive_group(required=True)
    preview_target.add_argument("--run", help="Completed run UUID")
    preview_target.add_argument("--project", help="Use the most recent finished run of this project")
    preview.add_argument("--limit", type=int, default=5, help="Review pairs in this preview, 1–25")
    preview.add_argument("--offset", type=int, default=0)
    preview.add_argument("--output", type=Path, required=True, help="Output prefix for .html and .json reports")
    legacy = commands.add_parser("import-legacy", help="Import old candidate inventory; the next scan establishes a fresh baseline")
    legacy.add_argument("--name", required=True)
    legacy.add_argument("--domains", type=Path, required=True)
    legacy.add_argument("--output", type=Path, required=True, help="Old company output folder including backups")
    return p


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        if args.command == "handoff-preview":
            from .store import Store
            from .preview import build_preview, write_preview
            # This read-only report does not acquire the scanner process lock and
            # can be generated while the local UI is open.
            if not (args.data_dir / "monitor.sqlite3").exists():
                raise ValueError("No saved scanner data exists in that folder.")
            store = Store(args.data_dir)
            run_id = args.run
            if args.project:
                runs = [run for run in store.list_runs(args.project) if run["status"] != "running"]
                if not runs:
                    raise ValueError("That project has no finished runs.")
                run_id = runs[0]["id"]
            report = build_preview(store, args.data_dir, run_id, limit=args.limit, offset=args.offset)
            for path in write_preview(report, args.output):
                print(path.resolve())
            print(f"{report['summary']['selected_pairs']} eligible pairs; this batch has {report['batch']['pairs']} pairs and {report['batch']['inline_image_bytes']} inline image bytes. External requests: 0.")
            return 0
        from .adapters import DnsResolver
        from .screenshots import GowitnessCapture
        capturer = None if args.no_screenshots else GowitnessCapture(
            executable=args.gowitness_path, chrome_path=args.chrome_path,
            timeout=args.capture_timeout, threads=args.capture_workers, driver=args.capture_driver,
            probe_timeout=args.web_timeout)
        with MonitorService(args.data_dir, discovery=not args.no_discovery,
                            resolver=DnsResolver(args.resolver, args.dns_timeout, args.workers),
                            max_candidates=args.max_candidates,
                            capture=not args.no_screenshots, capturer=capturer,
                            interval_hours=getattr(args, "interval_hours", 0), scheduling=args.command == "serve") as service:
            if args.command == "doctor":
                print(json.dumps(service.tool_status(), indent=2))
            elif args.command == "projects":
                print(json.dumps(service.store.list_projects(), indent=2))
            elif args.command == "demo":
                from .demo import seed_demo
                project = seed_demo(service)
                print(f"Created simulated demo: {project['name']} ({project['id']})")
                if args.report_output:
                    from .preview import build_preview, write_preview
                    run = service.store.list_runs(project["id"])[0]
                    for path in write_preview(build_preview(service.store, service.data_dir, run["id"]), args.report_output):
                        print(path.resolve())
            elif args.command == "import-legacy":
                from .legacy import import_inventory
                roots = parse_domains(args.domains.read_text(encoding="utf-8-sig"))
                project = import_inventory(service, args.name, roots, args.output)
                print(f"Imported inventory into {project['name']} ({project['id']}); run a scan to establish a baseline.")
            elif args.command == "scan":
                if args.project:
                    if args.domains:
                        p.error("--domains is only used with --name; project roots are immutable")
                    project = service.store.get_project(args.project)
                    if not project:
                        p.error("Unknown project ID")
                else:
                    if not args.domains:
                        p.error("--name requires --domains")
                    roots = parse_domains(args.domains.read_text(encoding="utf-8-sig"))
                    matches = [x for x in service.store.list_projects() if x["name"] == args.name.strip()]
                    project = matches[0] if matches else service.create_project(args.name, roots)
                    if project["roots"] != roots:
                        p.error("That project has different roots. Use a new name to establish a separate baseline.")
                result = service.scan_now(project["id"])
                print(json.dumps(result, indent=2))
                return 0 if result["status"] == "completed" else 2
            elif args.command == "serve":
                from waitress import serve
                from .web import create_app
                logging.info("Serving on http://%s:%s (data: %s)", args.host, args.port, service.data_dir)
                previous = signal.signal(signal.SIGTERM, _stop_server)
                try:
                    serve(create_app(service), host=args.host, port=args.port, threads=8)
                finally:
                    signal.signal(signal.SIGTERM, previous)
        return 0
    except KeyboardInterrupt:
        return 0
    except (ValueError, OSError, RuntimeError, ImportError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
