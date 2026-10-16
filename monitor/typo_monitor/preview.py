"""Local, metadata-only reports of the optional cloud handoff."""

import html
import json
from pathlib import Path

from PIL import Image

from .handoff import review_selection
from .handoff_images import MAX_EDGE, MAX_IMAGE_BYTES, image_payload


def build_preview(store, data_dir, run_id, *, limit=5, offset=0):
    if not 1 <= limit <= 25 or offset < 0:
        raise ValueError("Preview limit must be 1–25 and offset nonnegative.")
    selection = review_selection(store, run_id)
    items, cache = [], {}
    image_bytes = data_url_bytes = original_bytes = image_count = unavailable = 0
    for pair in selection["items"][offset:offset + limit]:
        item = {key: pair[key] for key in ("domain", "scheme", "visual_status")}
        item["images"] = []
        for role, capture in [("current", pair["current"]), ("previous", pair["previous"])] + [
                ("reference", reference) for reference in pair["references"]]:
            if not capture:
                continue
            key = (capture["run_id"], capture["domain"], capture["scheme"])
            if key not in cache:
                try:
                    payload = image_payload(data_dir, capture)
                    cache[key] = {**payload["image_transfer"], "data_url_bytes": len(payload["image_data_url"])}
                except (OSError, ValueError, Image.DecompressionBombError):
                    cache[key] = {"error": "Image unavailable or failed validation."}
            detail = {"role": role, "domain": capture["domain"], "run_id": capture["run_id"], **cache[key]}
            item["images"].append(detail)
            if "error" in detail:
                unavailable += 1
            else:
                image_count += 1
                image_bytes += detail["bytes"]
                original_bytes += detail["original_bytes"]
                data_url_bytes += detail["data_url_bytes"]
        item["ready"] = not any("error" in image for image in item["images"])
        items.append(item)
    total = len(selection["items"])
    return {"run_id": str(run_id), "summary": selection["summary"], "items": items,
            "limit": limit, "offset": offset,
            "next_offset": offset + limit if offset + limit < total else None,
            "batch": {"pairs": len(items), "ready_pairs": sum(item["ready"] for item in items),
                      "images": image_count, "unavailable_images": unavailable,
                      "original_image_bytes": original_bytes, "compact_image_bytes": image_bytes,
                      "inline_image_bytes": data_url_bytes},
            "limits": {"max_image_edge": MAX_EDGE, "max_image_bytes": MAX_IMAGE_BYTES, "max_references": 1},
            "external_requests": 0,
            "note": "Local preview only. No n8n or AI calls. Byte counts include repeated references and base64; prompts and HTTP/JSON overhead are additional. No image bytes are stored in this report."}


def _size(value):
    return f"{value / 1024:.1f} KiB" if value < 1024 * 1024 else f"{value / (1024 * 1024):.2f} MiB"


def write_preview(report, output):
    prefix = Path(output)
    if prefix.suffix in {".json", ".html"}:
        prefix = prefix.with_suffix("")
    prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path, html_path = Path(str(prefix) + ".json"), Path(str(prefix) + ".html")
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    summary, batch = report["summary"], report["batch"]
    exclusions = "".join(f"<li><strong>{count}</strong> {html.escape(reason.replace('_', ' '))}</li>"
                         for reason, count in summary["excluded"].items())
    rows = "".join("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in (
        item["domain"], item["scheme"].upper(), item["visual_status"], len(item["images"]),
        _size(sum(image.get("data_url_bytes", 0) for image in item["images"])),
        "Ready" if item["ready"] else "Image unavailable")) + "</tr>" for item in report["items"])
    html_path.write_text(f"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Typo Watch · Local handoff preview</title>
<style>body{{font:16px system-ui;background:#f4f7f5;color:#173e32;max-width:1050px;margin:40px auto;padding:0 24px}}h1{{font-size:34px}}.tag{{color:#35735d;font-size:13px;letter-spacing:.1em}}.metrics{{display:flex;flex-wrap:wrap;gap:16px;margin:28px 0}}.metrics div{{background:white;padding:20px;border-radius:12px;min-width:160px}}.metrics strong{{font-size:28px;display:block}}p{{line-height:1.6}}table{{width:100%;border-collapse:collapse;background:white}}th,td{{padding:12px;text-align:left;border-bottom:1px solid #e1e9e4}}.scroll{{overflow:auto}}ul{{display:flex;gap:18px;flex-wrap:wrap;padding:0;list-style:none}}small{{color:#527164}}</style>
<div class="tag">TYPO WATCH / LOCAL ONLY</div><h1>Review the volume before connecting n8n.</h1>
<p>Run <code>{html.escape(report['run_id'])}</code></p>
<div class="metrics"><div><strong>{summary['total_captures']}</strong>capture attempts</div><div><strong>{summary['selected_pairs']}</strong>eligible review pairs</div><div><strong>{batch['pairs']}</strong>pairs in this batch</div><div><strong>{_size(batch['inline_image_bytes'])}</strong>inline images in this batch</div></div>
<h2>Kept out of the handoff</h2><ul>{exclusions}</ul>
<p>Original files for this batch: {_size(batch['original_image_bytes'])}. Compact copies: {_size(batch['compact_image_bytes'])}. Resizing affects only optional handoff copies; the local gallery retains full screenshots.</p>
<h2>Batch preview</h2><div class="scroll"><table><thead><tr><th>Candidate</th><th>Protocol</th><th>Local result</th><th>Images</th><th>Inline size</th><th>Readiness</th></tr></thead><tbody>{rows or '<tr><td colspan="6">No images need review in this batch.</td></tr>'}</tbody></table></div>
<p>{'More candidates remain. Next offset: ' + str(report['next_offset']) + '.' if report['next_offset'] is not None else 'This is the last batch in this preview.'}</p>
<p><small>{html.escape(report['note'])} These are byte counts, not model-token or price estimates. A first scan can have many eligible candidates; begin with a small batch.</small></p></html>""", encoding="utf-8")
    return json_path, html_path
