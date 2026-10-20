"""Group complete HTML and self-host templates within one client's run."""

import hashlib
import json

from .body_templates import TEMPLATE_VERSION


def group_report_entries(entries):
    # Either exact HTML OR the domain-normalized template can link pages.
    # Keep exact matches even when one page names another member's hostname.
    parents, owners, prepared = [], {}, []

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
        keys = [hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode("ascii")).hexdigest()
                for identity in identities]
        for key in keys:
            if key in owners:
                first, second = root(index), root(owners[key])
                if first != second:
                    parents[max(first, second)] = min(first, second)
            else:
                owners[key] = index
        prepared.append((entry, complete, min(keys)))

    buckets = {}
    for index, (entry, complete, group_id) in enumerate(prepared):
        group = buckets.setdefault(root(index), {"group_id": group_id, "members": [], "complete_body": complete})
        group["group_id"] = min(group["group_id"], group_id)
        group["members"].append(entry)

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
        if group["shared"]:
            group["reason"] = "Shared page template" if group["match_kind"] == "domain_template" else "Shared HTML body"
        groups.append(group)
    return groups
