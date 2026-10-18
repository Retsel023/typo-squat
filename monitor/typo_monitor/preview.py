"""Local measurement of the optional text-only cloud handoff; no network I/O."""

import html
import json
from pathlib import Path

from .text_review import review_selection, pack_pair


def build_preview(store, data_dir, run_id, *, limit=5, offset=0):
    if not 1 <= limit <= 25 or offset < 0:
        raise ValueError("Preview limit must be 1–25 and offset nonnegative.")
    selection = review_selection(store, run_id)
    items = []
    for pair in selection["items"][offset:offset + limit]:
        evidence = pack_pair(pair, include_text=True)
        encoded = json.dumps(evidence, ensure_ascii=False)
        # Measure the exact text payload locally without copying it into the
        # preview report. Prompts and n8n/HTTP envelopes are additional.
        items.append({"domain": pair["domain"], "scheme": pair["scheme"], "change_status": pair["change_status"],
                      "characters": len(encoded), "bytes": len(encoded.encode("utf-8")),
                      "has_previous": bool(pair["previous"]), "references": len(pair["references"])})
    total = len(selection["items"])
    return {"run_id": str(run_id), "summary": selection["summary"], "items": items,
            "limit": limit, "offset": offset, "next_offset": offset + limit if offset + limit < total else None,
            "batch": {"pairs": len(items), "characters": sum(item["characters"] for item in items),
                      "text_bytes": sum(item["bytes"] for item in items), "images": 0},
            "limits": {"current_text_chars": 8000, "previous_text_chars": 2000,
                       "reference_text_chars": 2000, "diff_chars": 2600, "max_references": 1},
            "external_requests": 0,
            "note": "Text-only handoff preview. No text bodies or images are embedded, no external calls. Counts include repeated references and JSON escaping; the system prompt and transport envelopes are additional. Characters/bytes are not token or price estimates."}


def write_preview(report, output):
    prefix = Path(output)
    if prefix.suffix in {".json", ".html"}:
        prefix = prefix.with_suffix("")
    prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path, html_path = Path(str(prefix) + ".json"), Path(str(prefix) + ".html")
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    exclusions = "".join(f"<li>{html.escape(reason.replace('_', ' '))}: <strong>{count}</strong></li>"
                         for reason, count in report["summary"]["excluded"].items())
    rows = "".join("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in (
        item["domain"], item["scheme"].upper(), item["change_status"], item["characters"], item["bytes"])) + "</tr>"
        for item in report["items"])
    html_path.write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Typo Watch · Text handoff preview</title>
<style>body{{font:16px system-ui;background:#f4f7f5;color:#173e32;max-width:1050px;margin:40px auto;padding:0 24px}}h1{{font-size:32px}}p{{line-height:1.6}}table{{width:100%;border-collapse:collapse;background:white}}th,td{{padding:12px;text-align:left;border-bottom:1px solid #e1e9e4}}.scroll{{overflow:auto}}small{{color:#527164}}</style>
<h1>Text review volume · local only</h1><p>Run {html.escape(report['run_id'])}</p>
<p>{report['summary']['selected_pairs']} eligible pairs. This batch: {report['batch']['pairs']} pairs,
{report['batch']['characters']} characters / {report['batch']['text_bytes']} UTF-8 bytes. Images: 0.</p>
<h2>Kept out of the handoff</h2><ul>{exclusions}</ul>
<div class="scroll"><table><thead><tr><th>Candidate</th><th>Protocol</th><th>Change</th><th>Characters</th><th>Bytes</th></tr></thead><tbody>{rows or '<tr><td colspan="5">No complete new or changed text in this batch.</td></tr>'}</tbody></table></div>
<p>{'Next offset: ' + str(report['next_offset']) if report['next_offset'] is not None else 'Last page.'}</p>
<p><small>{html.escape(report['note'])}</small></p></html>''', encoding="utf-8")
    return json_path, html_path
