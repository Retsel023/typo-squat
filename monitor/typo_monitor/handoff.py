"""Select a small review queue from local capture metadata without image I/O."""

from __future__ import annotations


def review_selection(store, run_id, *, include_parked=False, include_reviewed=False):
    """Return new/changed candidate pairs with distinct comparison histories.

    Each capture receives at most one exclusion, in this priority: original,
    title_filtered, failed, unchanged, uncertain, parked, reviewed, duplicate. Parking uses the
    project's current classification; capture history itself remains immutable.
    References are limited to one successfully captured source from this run.
    """
    run_id = str(run_id)
    run = store.get_run(run_id)
    if run is None:
        raise ValueError("Scan not found.")
    if run["status"] == "running":
        raise ValueError("The scan is still running.")
    captures = store.list_run_captures(run_id)
    originals = set(store.inventory(run["project_id"])["seeds"])
    by_key = {(capture["domain"], capture["scheme"]): capture for capture in captures}
    excluded = dict.fromkeys(("original", "title_filtered", "failed", "unchanged", "uncertain", "duplicate", "parked", "reviewed"), 0)
    states, previous_captures = {}, {}

    def state(domain):
        if domain not in states:
            states[domain] = store.get_domain(run["project_id"], domain) or {}
        return states[domain]

    def previous(capture):
        old_id = (capture.get("visual") or {}).get("previous_run_id")
        if not old_id:
            return None
        key = (old_id, capture["domain"], capture["scheme"])
        if key not in previous_captures:
            old = store.get_capture(*key)
            previous_captures[key] = old if (old and old["project_id"] == run["project_id"]
                                                       and old["status"] == "captured") else None
        return previous_captures[key]

    def redundant(capture):
        visual = capture.get("visual") or {}
        if visual.get("duplicate_kind") != "exact" or not visual.get("duplicate_of"):
            return False
        other = by_key.get((capture["domain"], visual["duplicate_of"]))
        other_visual = (other or {}).get("visual") or {}
        if not other or other["status"] != "captured" or other_visual.get("change") not in {"first_capture", "changed"}:
            return False
        # A stale/inconsistent cue must never erase a different current image.
        digest, other_digest = visual.get("pixel_sha256"), other_visual.get("pixel_sha256")
        if digest and other_digest and digest != other_digest:
            return False
        if visual.get("change") == other_visual.get("change") == "first_capture":
            return True
        old, other_old = previous(capture), previous(other)
        old_digest = ((old or {}).get("visual") or {}).get("pixel_sha256")
        return bool(old_digest and old_digest == ((other_old or {}).get("visual") or {}).get("pixel_sha256"))

    items = []
    for capture in captures:
        domain = capture["domain"]
        change = (capture.get("visual") or {}).get("change")
        reason = None
        if domain in originals:
            reason = "original"
        elif (capture.get("preflight") or {}).get("skip_reason") == "title_rule":
            reason = "title_filtered"
        elif capture["status"] != "captured":
            reason = "failed"
        elif change == "unchanged":
            reason = "unchanged"
        elif change not in {"first_capture", "changed"}:
            reason = "uncertain"
        elif not include_parked and (state(domain).get("parking") or {}).get("status") == "likely_parked":
            reason = "parked"
        elif not include_reviewed and capture.get("analysis"):
            reason = "reviewed"
        elif redundant(capture):
            reason = "duplicate"
        if reason:
            excluded[reason] += 1
            continue
        references = []
        for seed in state(domain).get("sources", []):
            reference = next((by_key.get((seed, scheme)) for scheme in ("https", "http")
                              if by_key.get((seed, scheme), {}).get("status") == "captured"), None)
            if reference:
                references.append(reference)
                break
        items.append({"domain": domain, "scheme": capture["scheme"],
                      "visual_status": "new" if change == "first_capture" else "changed",
                      "current": capture, "previous": previous(capture), "references": references})
    return {"run_id": run_id, "items": items,
            "summary": {"total_captures": len(captures), "selected_pairs": len(items), "excluded": excluded}}
