#!/usr/bin/env python3
"""Normalize `bumper list --format json` into the federated advisory shape.

The Go binary emits enforced rules as:
    {id, severity, source(origin), resource(str), title, fix, refs[], avd?}
The advisor index wants every row in one shape:
    {enforced, source, source_id, provider, severity, resources[], title,
     remediation, refs[], category, cwe}

Usage:  bumper list --format json | normalize_enforced.py > data/enforced.json
"""
import sys
import json

PROVIDER_BY_ID = (("AWS_", "aws"), ("GCP_", "gcp"), ("GOOGLE_", "gcp"), ("AZURE_", "azure"))
PROVIDER_BY_RESOURCE = (
    ("aws_", "aws"),
    ("google_", "gcp"),
    ("azurerm_", "azure"),
    ("azuread_", "azure"),
    ("azapi_", "azure"),
)


def provider_of(rule: dict) -> str:
    rid = (rule.get("id") or "").upper()
    for prefix, prov in PROVIDER_BY_ID:
        if rid.startswith(prefix):
            return prov
    res = (rule.get("resource") or "").lower()
    for prefix, prov in PROVIDER_BY_RESOURCE:
        if res.startswith(prefix):
            return prov
    return ""


def main() -> None:
    rules = json.load(sys.stdin)
    out = []
    for r in rules:
        resource = r.get("resource") or ""
        out.append({
            "enforced": 1,
            "source": "bumper",
            "source_id": r.get("id", ""),
            "provider": provider_of(r),
            "severity": r.get("severity", ""),
            "resources": [resource] if resource else [],
            "title": r.get("title", ""),
            "remediation": r.get("fix", ""),
            "refs": r.get("refs", []) or [],
            "category": "enforced",
            "cwe": "",
            # keep the upstream AVD id (if any) so it's searchable / referenceable
            "avd": r.get("avd", ""),
        })
    json.dump(out, sys.stdout, indent=1)
    print(f"normalized {len(out)} enforced rules", file=sys.stderr)


if __name__ == "__main__":
    main()
