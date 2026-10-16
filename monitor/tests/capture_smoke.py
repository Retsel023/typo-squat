"""Explicit local-only Gowitness/Chromium smoke test and demo asset builder.

Run manually with --gowitness and --chrome; no external websites are visited.
This is separate from unittest discovery because it requires browser binaries.
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading


STYLE = """*{box-sizing:border-box}body{margin:0;background:#f5f8fa;color:#162b3b;font:18px Arial,sans-serif}
.fixture{background:#fff2c9;color:#685110;padding:12px 32px;font-size:14px;text-align:center}
header{background:#fff;border-bottom:1px solid #dfe7eb;padding:28px 70px;display:flex;justify-content:space-between}
header b{font-size:28px}header span{font-size:16px;color:#586c79}main{display:flex;gap:90px;max-width:1100px;margin:65px auto}
.intro{flex:1;padding-top:32px}h1{font-size:43px;line-height:1.12;margin:20px 0}p{color:#536976;line-height:1.65}
.eyebrow{font-size:13px;letter-spacing:2px;color:#27755f;text-transform:uppercase}.card{width:400px;background:white;border:1px solid #e0e7ea;border-radius:14px;padding:32px;box-shadow:0 12px 30px #102a3910}
h2{font-size:26px;margin:0 0 10px}label{display:block;font-size:14px;margin:24px 0 10px}.input{border:1px solid #cfdbe1;padding:15px;border-radius:6px;color:#8b9ca7;font-size:15px}
.button{background:#26755d;color:white;text-align:center;border-radius:6px;padding:15px;margin-top:25px;font-size:16px}.link{font-size:14px;color:#26755d;margin-top:20px}
.parked{background:#fcf7ec}.parked main{max-width:1000px;display:block;text-align:center}.parked h1{font-size:54px;margin:28px auto}.parked .card{margin:35px auto;width:490px}.price{font-size:43px;font-weight:bold;margin:15px}.tiny{font-size:13px;color:#77858e}
"""


def fixture_page(kind):
    if kind == "parked":
        content = """<main><div class="eyebrow">Domain marketplace · local fixture</div><h1>This domain is for sale</h1><p>A sample sales lander for testing the parking review view.</p><div class="card"><h2>Example domain</h2><div class="price">€ 2,495</div><p>Secure purchase · sample content only</p><div class="button">Make an offer — inactive example</div></div></main>"""
    else:
        impersonation = kind == "imitation"
        content = """<main><section class="intro"><div class="eyebrow">Your team's workspace</div><h1>Everything your team<br>needs, together.</h1><p>Access your documents, projects and team updates in one place.</p><p class="tiny">This page is a local test fixture. There is no real sign-in.</p></section><section class="card"><h2>Welcome back</h2><p>Sign in to Example Workspace</p><label>Work email</label><div class="input">name@example.com</div><label>Password</label><div class="input">••••••••••••</div>"""
        if impersonation:
            content += '<label>Recovery code</label><div class="input">Enter your recovery code</div>'
        content += '<div class="button">Continue — inactive example</div><div class="link">Need help signing in?</div></section></main>'
    label = {"reference": "REFERENCE PAGE", "imitation": "LOOKALIKE PAGE", "parked": "PARKING PAGE"}[kind]
    return f'<!doctype html><html><head><meta charset="utf-8"><title>Local capture fixture · {label}</title><style>{STYLE}</style></head><body class="{kind}"><div class="fixture">SIMULATED LOCAL FIXTURE — {label} — no external domain was visited</div><header><b>◈ Example Workspace</b><span>Workspace access</span></header>{content}</body></html>'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gowitness", required=True)
    parser.add_argument("--chrome", required=True)
    parser.add_argument("--driver", choices=["chromedp", "gorod"], default="chromedp")
    parser.add_argument("--demo-assets", type=Path, help="Optionally save the three labeled fixture PNGs here")
    args = parser.parse_args()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            kind = self.path.lstrip("/").split("?", 1)[0]
            if kind not in {"reference", "imitation", "parked"}:
                self.send_error(404)
                return
            body = fixture_page(kind).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="typo-capture-smoke-") as directory:
            workdir = Path(directory)
            targets = {f"http://127.0.0.1:{server.server_port}/{kind}": kind for kind in ("reference", "imitation", "parked")}
            (workdir / "targets.txt").write_text("\n".join(targets) + "\n", encoding="utf-8")
            images = workdir / "images"
            result = subprocess.run([args.gowitness, "scan", "file", "-f", str(workdir / "targets.txt"),
                "--chrome-path", args.chrome, "--driver", args.driver, "--screenshot-path", str(images), "--screenshot-format", "png",
                "--write-jsonl", "--write-jsonl-file", str(workdir / "captures.jsonl"), "--threads", "1",
                "--delay", "1", "--timeout", "25", "--skip-html", "--skip-network-logs", "--log-scan-errors"],
                capture_output=True, text=True, timeout=90)
            if result.returncode:
                raise RuntimeError(result.stderr[-3000:])
            records = [json.loads(line) for line in (workdir / "captures.jsonl").read_text().splitlines() if line.strip()]
            if {row["url"] for row in records} != set(targets) or any(row.get("failed") for row in records):
                summary = [{key: row.get(key) for key in ("url", "failed", "failed_reason")} for row in records]
                raise RuntimeError(f"Incomplete real capture results: {summary}")
            if args.demo_assets:
                args.demo_assets.mkdir(parents=True, exist_ok=True)
            for row in records:
                image = images / row["file_name"]
                if not image.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"):
                    raise RuntimeError("Gowitness did not produce a PNG image.")
                if args.demo_assets:
                    shutil.copyfile(image, args.demo_assets / f"{targets[row['url']]}.png")
            print(json.dumps({"local_captures": len(records), "statuses": [row["response_code"] for row in records],
                              "demo_assets": str(args.demo_assets) if args.demo_assets else None}))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    main()
