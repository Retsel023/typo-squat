"""Group complete HTML and self-host templates within one client's run."""

import hashlib
import json

from .body_templates import TEMPLATE_VERSION
from .content_groups import CONTENT_GROUP_VERSION


_TITLE_OPTIONAL_ID = "main-content-missing-title-v1"


def _main_content_identity(probe):
    if (probe.get("status") == "http_response" and probe.get("body_sha256")
            and probe.get("body_status", "complete") == "complete"
            and probe.get("body_content_group_version") == CONTENT_GROUP_VERSION
            and probe.get("body_content_group_status") == "complete"
            and probe.get("body_content_group_sha256") and probe.get("body_content_group_main_sha256")
            and isinstance(probe.get("body_content_type"), str)):
        return (_TITLE_OPTIONAL_ID, probe["body_content_group_main_sha256"],
                probe["body_content_type"].split(";", 1)[0].strip())
    return None


def group_report_entries(entries):
    # Either exact HTML OR the domain-normalized template can link pages.
    # Keep exact matches even when one page names another member's hostname.
    entries = list(entries)
    parents, owners, prepared, content_links, titleless_links = [], {}, [], [], []
    title_families = {}
    for entry in entries:
        probe = entry["capture"].get("preflight", {})
        identity = _main_content_identity(probe)
        if identity is not None and probe.get("title_status") == "found" and probe.get("title"):
            title_families.setdefault(identity, set()).add(probe["body_content_group_sha256"])

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
        main_identity = _main_content_identity(probe)
        # A missing title can join only one unambiguous titled family. Never
        # let an untitled page bridge conflicting nonempty static titles.
        if (main_identity is not None and len(title_families.get(main_identity, ())) == 1
                and (probe.get("title_status") == "found" and probe.get("title")
                     or probe.get("title_status") == "missing" and not probe.get("title"))):
            identities.append(main_identity)
        keys = [hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode("ascii")).hexdigest()
                for identity in identities]
        for key, identity in zip(keys, identities):
            if key in owners:
                first, second = root(index), root(owners[key])
                if first != second:
                    parents[max(first, second)] = min(first, second)
                    if identity[0] in {CONTENT_GROUP_VERSION, _TITLE_OPTIONAL_ID}:
                        content_links.append(index)
                    if identity[0] == _TITLE_OPTIONAL_ID:
                        titleless_links.append(index)
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
    for index in titleless_links:
        buckets[root(index)]["missing_title_grouping"] = True

    groups = []
    for group in buckets.values():
        members = group["members"]
        example = max(members, key=lambda entry: (entry.get("has_image", entry["capture"].get("status") == "captured"),
                                                  entry["capture"]["scheme"] == "https"))
        group.update(example)
        domains = sorted({entry["capture"]["domain"] for entry in members})
        group.update(domain_count=len(domains), domain_preview=domains[:5],
                     endpoint_count=sum(len(entry["schemes"]) for entry in members),
                     member_count=len(members), shared=len(members) > 1,
                     has_image=any(member.get("has_image", member["capture"].get("status") == "captured")
                                   for member in members),
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
    return _pair_protocol_views(groups)


def _pair_protocol_views(groups):
    """Pair equal domain sets for display, without claiming equal content."""
    candidates = {}
    for index, group in enumerate(groups):
        schemes = {scheme for member in group["members"] for scheme in member["schemes"]}
        if schemes in ({"http"}, {"https"}):
            domains = tuple(sorted({member["capture"]["domain"] for member in group["members"]}))
            candidates.setdefault(domains, []).append((index, next(iter(schemes))))
    replacements, removed = {}, set()
    for domains, matches in candidates.items():
        if len(matches) != 2 or {scheme for _, scheme in matches} != {"http", "https"}:
            continue
        views = [groups[index] for index, _ in sorted(matches, key=lambda match: match[1])]
        members = sorted((member for view in views for member in view["members"]),
                         key=lambda entry: (entry["capture"]["domain"], entry["capture"]["scheme"]))
        identity = ["protocol-pair-v2", domains, [view["group_id"] for view in views]]
        pair = dict(views[0])
        pair.update(group_id=hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode("ascii")).hexdigest(),
                    members=members, member_count=len(members), protocol_views=views,
                    endpoint_count=sum(view["endpoint_count"] for view in views), schemes=["http", "https"],
                    has_image=any(view["has_image"] for view in views),
                    match_kind="protocol_pair", complete_body=False, shared=len(domains) > 1,
                    reason="HTTP / HTTPS groups" if len(domains) > 1 else "HTTP / HTTPS views")
        indices = sorted(index for index, _ in matches)
        replacements[indices[0]] = pair
        removed.add(indices[1])
    return [replacements.get(index, group) for index, group in enumerate(groups) if index not in removed]
