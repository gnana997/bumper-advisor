"""Container CVE domain — shared config, normalization, and version matching.

Holds the pieces used by BOTH ingest (scripts/sync_cve_pg.py) and query
(search_pg.lookup_cve): the configured ecosystem set, input aliases, per-ecosystem
package normalization, severity derivation, the OSV-ecosystem -> univers scheme map,
and the range-match engine. Keeping them here guarantees ingest and query normalize
identically — otherwise a query silently returns empty (the worst failure mode for a
security tool).
"""
import os
import re

# --- which OSV ecosystems we mirror ------------------------------------------
# Languages (exact names) + key OS distros (matched by prefix, since distros are
# sub-ecosystems like "Debian:12", "Alpine:v3.19", "Ubuntu:22.04").
LANGUAGE_ECOSYSTEMS = ["npm", "PyPI", "Go", "Maven", "RubyGems", "crates.io", "NuGet"]
DISTRO_PREFIXES = ["Debian", "Ubuntu", "Alpine", "Red Hat", "Rocky Linux", "AlmaLinux"]


def configured_ecosystems():
    """(languages, distro_prefixes). Override for local/measurement runs with
    CVE_ECOSYSTEMS, e.g. CVE_ECOSYSTEMS="PyPI" or "PyPI,npm"."""
    env = os.environ.get("CVE_ECOSYSTEMS")
    if env:
        return [e.strip() for e in env.split(",") if e.strip()], []
    return list(LANGUAGE_ECOSYSTEMS), list(DISTRO_PREFIXES)


def select_ecosystems(available):
    """From the live ecosystems.txt list, keep exact language matches + any
    sub-ecosystem whose name starts with a configured distro prefix."""
    langs, prefixes = configured_ecosystems()
    chosen = []
    for eco in available:
        if eco in langs or any(eco == p or eco.startswith(p + ":") for p in prefixes):
            chosen.append(eco)
    return chosen


# --- input ecosystem aliases (user/agent input -> OSV canonical) -------------
ECOSYSTEM_ALIASES = {
    "pypi": "PyPI", "pip": "PyPI", "python": "PyPI",
    "npm": "npm", "npmjs": "npm", "node": "npm",
    "go": "Go", "golang": "Go",
    "maven": "Maven", "java": "Maven",
    "rubygems": "RubyGems", "gem": "RubyGems", "ruby": "RubyGems",
    "crates.io": "crates.io", "crates": "crates.io", "cargo": "crates.io", "rust": "crates.io",
    "nuget": "NuGet", "dotnet": "NuGet",
}


def canonical_ecosystem(eco):
    """Map a user/agent ecosystem string to OSV's canonical casing.
    Returns None for unknown/ambiguous (caller -> status: ecosystem_unsupported).
    Exact OSV forms (incl. distro sub-ecosystems like "Debian:12") pass through."""
    e = (eco or "").strip()
    if not e:
        return None
    if e in LANGUAGE_ECOSYSTEMS or ":" in e:
        return e
    return ECOSYSTEM_ALIASES.get(e.lower())


# --- per-ecosystem package normalization (IDENTICAL at ingest + query) --------
_PEP503 = re.compile(r"[-_.]+")


def normalize_package(ecosystem, name):
    """Normalize a package name per its ecosystem's rules. Applied the same way
    when ingesting OSV records and when answering a query, so they match."""
    name = (name or "").strip()
    base = ecosystem.split(":", 1)[0]
    if base == "PyPI":
        return _PEP503.sub("-", name).lower()          # PEP 503
    if base in ("Go", "Maven"):
        return name                                    # case/separator-sensitive
    if base == "npm":
        # npm names are lowercase; keep the @scope/ prefix and the slash intact
        return name if name.startswith("@") else name.lower()
    return name.lower()                                # distros etc. are lowercase


# --- canonical id (collapse GHSA/PYSEC/DSA aliases of the same CVE) -----------
_CVE_RE = re.compile(r"CVE-\d{4}-\d+")


def canonical_id(vuln_id, aliases):
    """One id per underlying vuln for the search corpus: prefer the CVE. Distro
    per-CVE records (DEBIAN-CVE-…/UBUNTU-CVE-…) embed the CVE in the id but often
    have empty aliases, so fall back to extracting it — this merges the thin distro
    record into the rich GHSA/CVE doc instead of leaving a duplicate."""
    if (vuln_id or "").startswith("CVE-"):
        return vuln_id
    for a in aliases or []:
        if a.startswith("CVE-"):
            return a
    m = _CVE_RE.search(vuln_id or "")
    return m.group(0) if m else vuln_id


# --- severity: CVSS vector -> GHSA/distro severity word -> none ---------------
_CVSS_RANK = {"CVSS_V4": 3, "CVSS_V3": 2, "CVSS_V2": 1}
# qualitative words used by GHSA + the distro feeds, mapped to our 4-tier
_WORD_TIER = {
    "CRITICAL": "critical",
    "HIGH": "high", "IMPORTANT": "high",
    "MEDIUM": "medium", "MODERATE": "medium",
    "LOW": "low", "NEGLIGIBLE": "low",
}


def _tier_from_score(score):
    return ("critical" if score >= 9 else "high" if score >= 7
            else "medium" if score >= 4 else "low")


def _score_from_cvss(sev_list):
    best_rank, best_score = -1, None
    for s in sev_list or []:
        typ, vec = s.get("type"), s.get("score")
        if not vec:
            continue
        try:
            if typ == "CVSS_V4":
                from cvss import CVSS4
                score = float(CVSS4(vec).base_score)
            elif typ == "CVSS_V3":
                from cvss import CVSS3
                score = float(CVSS3(vec).base_score)
            elif typ == "CVSS_V2":
                from cvss import CVSS2
                score = float(CVSS2(vec).base_score)
            else:
                continue
        except Exception:
            continue
        rank = _CVSS_RANK.get(typ, 0)
        if rank > best_rank:
            best_rank, best_score = rank, score
    return best_score


def _word_tier(val):
    return _WORD_TIER.get(val.strip().upper()) if isinstance(val, str) else None


def severity_from_osv(rec):
    """(score|None, tier|''). Fallback chain over fields ALREADY in the OSV record:
    CVSS vector -> GHSA `database_specific.severity` word -> distro severity word."""
    score = _score_from_cvss(rec.get("severity"))
    if score is not None:
        return score, _tier_from_score(score)
    tier = _word_tier((rec.get("database_specific") or {}).get("severity"))
    if tier:
        return None, tier
    for aff in rec.get("affected", []):
        for blk in (aff.get("ecosystem_specific"), aff.get("database_specific")):
            tier = _word_tier((blk or {}).get("severity"))
            if tier:
                return None, tier
    return None, ""


# --- version matcher: OSV ranges -> univers ----------------------------------
ECOSYSTEM_TO_UNIVERS = {
    "PyPI": "pypi", "npm": "npm", "Go": "golang", "Maven": "maven",
    "RubyGems": "gem", "crates.io": "cargo", "NuGet": "nuget",
    "Debian": "deb", "Ubuntu": "deb", "Alpine": "alpine",
    "Red Hat": "rpm", "Rocky Linux": "rpm", "AlmaLinux": "rpm",
}

from univers.versions import (  # noqa: E402
    PypiVersion, SemverVersion, DebianVersion, RpmVersion, AlpineLinuxVersion,
    MavenVersion, RubygemsVersion, NugetVersion, GolangVersion,
)

_VCLASS = {
    "pypi": PypiVersion, "npm": SemverVersion, "golang": GolangVersion,
    "maven": MavenVersion, "gem": RubygemsVersion, "cargo": SemverVersion,
    "nuget": NugetVersion, "deb": DebianVersion, "rpm": RpmVersion,
    "alpine": AlpineLinuxVersion,
}


def _vclass(ecosystem):
    scheme = ECOSYSTEM_TO_UNIVERS.get((ecosystem or "").split(":", 1)[0])
    return _VCLASS.get(scheme, SemverVersion)


def _ge(v, bound, VC):
    if bound == "0":           # OSV: introduced "0" sorts before everything
        return True
    try:
        return v >= VC(bound)
    except Exception:
        return False


def _cmp(v, bound, VC, op):
    try:
        return op(v, VC(bound))
    except Exception:
        return False


def match(version, versions_list, ranges, ecosystem):
    """Is `version` affected, and (if known) the fix version. Returns (bool, str|None).

    Prefer the RANGE sweep — it compares with the ecosystem's version semantics, so
    "3.2.0" correctly matches an OSV range stated as "3.2" (PEP440 equal). affected
    iff introduced <= v < fixed (fixed EXCLUSIVE) or introduced <= v <= last_affected
    (inclusive). "0"=-inf, open upper=+inf. GIT skipped. Fall back to the enumerated
    `versions[]` set only when there are no usable ranges (or the version won't parse).
    """
    VC = _vclass(ecosystem)
    usable = [r for r in (ranges or []) if r.get("type") in ("ECOSYSTEM", "SEMVER")]
    if usable:
        try:
            v = VC(version)
        except Exception:
            return (version in (versions_list or [])), None
        for r in usable:
            introduced = None
            for e in r.get("events", []):
                if "introduced" in e:
                    introduced = e["introduced"]
                elif "fixed" in e:
                    if introduced is not None and _ge(v, introduced, VC) \
                            and _cmp(v, e["fixed"], VC, lambda a, b: a < b):
                        return True, e["fixed"]
                    introduced = None
                elif "last_affected" in e:
                    if introduced is not None and _ge(v, introduced, VC) \
                            and _cmp(v, e["last_affected"], VC, lambda a, b: a <= b):
                        return True, None
                    introduced = None
            if introduced is not None and _ge(v, introduced, VC):
                return True, None
        return False, None
    return (version in (versions_list or [])), None
