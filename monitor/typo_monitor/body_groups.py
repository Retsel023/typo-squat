"""Group complete HTML and self-host templates within one client's run."""

import hashlib
import json

from .body_templates import TEMPLATE_VERSION
from .content_groups import CONTENT_GROUP_VERSION


def group_report_entries(entries):
    # Either exact HTML OR the domain-normalized template can link pages.
    # Keep exact matches even when one page names another member's hostname.
    parents, owners, prepared, content_links = [], {}, [], []

    def root(index):
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    for index, entry in enumerate(entries):
        parents.append(index)
        capture = entry["capture"]
        probe = capture.get("preflight", {})
        body_hash = probe.get("body_sha256")
        # Legacy fingerprints were also produced only after EOF. Missing or
        # partial bodies stay individual; equal titles/text are insufficient.
        complete = (probe.get("status") == "http_response" and bool(body_hash)
                    and probe.get("body_status", "complete") == "complete"
                    and probe.get("body_content_type") is not None)
        identities = [("html-v1", body_hash, probe["body_content_type"])] if complete else [
            ("endpoint-v1", capture["domain"], capture["scheme"])]
        template_hash = probe.get("body_template_sha256")
        if complete and template_hash and probe.get("body_template_version") == TEMPLATE_VERSION:
            identities.append((TEMPLATE_VERSION, template_hash, probe["body_content_type"]))
        content_hash = probe.get("body_content_group_sha256")
        if complete and content_hash and probe.get("body_content_group_version") == CONTENT_GROUP_VERSION:
            media_type = probe["body_content_type"].split(";", 1)[0].strip()
            identities.append((CONTENT_GROUP_VERSION, content_hash, media_type))
        keys = [hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode("ascii")).hexdigest()
                for identity in identities]
        for key, identity in zip(keys, identities):
            if key in owners:
                first, second = root(index), root(owners[key])
                if first != second:
                    parents[max(first, second)] = min(first, second)
                    if identity[0] == CONTENT_GROUP_VERSION:
                        content_links.append(index)
            else:
                owners[key] = index
        prepared.append((entry, complete, min(keys)))

    buckets = {}
    for index, (entry, complete, group_id) in enumerate(prepared):
        group = buckets.setdefault(root(index), {"group_id": group_id, "members": [], "complete_body": complete})
        group["group_id"] = min(group["group_id"], group_id)
        group["members"].append(entry)
    for index in content_links:
        buckets[root(index)]["similar_content"] = True

    groups = []
    for group in buckets.values():
        members = group["members"]
        example = max(members, key=lambda entry: (entry["capture"].get("status") == "captured",
                                                  entry["capture"]["scheme"] == "https"))
        group.update(example)
        domains = sorted({entry["capture"]["domain"] for entry in members})
        group.update(domain_count=len(domains), domain_preview=domains[:5],
                     endpoint_count=sum(len(entry["schemes"]) for entry in members),
                     member_count=len(members), shared=len(members) > 1,
                     rendered_title_count=len({entry["capture"].get("title") for entry in members
                                               if entry["capture"].get("title")}))
        group["match_kind"] = ("domain_template" if len({entry["capture"].get("preflight", {}).get("body_sha256")
                                                      for entry in members}) > 1 else "exact")
        if group.get("similar_content"):
            group["match_kind"] = "similar_content"
        group["ignored_consent_blocks"] = sum(entry["capture"].get("preflight", {}).get("body_content_group_ignored_consent", 0)
                                               for entry in members)
        if group["shared"]:
            group["reason"] = {"similar_content": "Similar content", "domain_template": "Shared page template",
                               "exact": "Shared HTML body"}[group["match_kind"]]
        groups.append(group)
    return _pair_unmatched_protocols(groups)


def _pair_unmatched_protocols(groups):
    """A visual fallback, explicitly without a body-equality claim."""
    candidates = {}
    for index, group in enumerate(groups):
        if not group["shared"] and group["member_count"] == 1 and len(group["schemes"]) == 1:
            candidates.setdefault(group["capture"]["domain"], []).append(index)
    replacements, removed = {}, set()
    for domain, indices in candidates.items():
        if len(indices) != 2 or {groups[index]["capture"]["scheme"] for index in indices} != {"http", "https"}:
            continue
        members = sorted((groups[index]["members"][0] for index in indices), key=lambda entry: entry["capture"]["scheme"])
        pair = dict(groups[indices[0]])
        pair.update(group_id=hashlib.sha256(("protocol-pair-v1\x00" + domain).encode()).hexdigest(),
                    members=members, member_count=2, endpoint_count=2, schemes=["http", "https"],
                    match_kind="protocol_pair", complete_body=False, shared=False, reason="HTTP / HTTPS views")
        replacements[indices[0]] = pair
        removed.add(indices[1])
    return [replacements.get(index, group) for index, group in enumerate(groups) if index not in removed]
