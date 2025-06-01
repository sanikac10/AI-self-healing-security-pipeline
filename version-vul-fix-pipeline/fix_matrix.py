"""fix_matrix.py  (v2.1)
Derive `fixes_available` using OSV query endpoint, but now **filter out
non‑PEP440 strings** (e.g. Git SHAs) so Version() doesn’t crash.
"""
from __future__ import annotations
import json, requests, time
from typing import List, Dict, Set
from packaging.version import Version, InvalidVersion
from autoheal_types import Finding

OSV_QUERY = "https://api.osv.dev/v1/query"


def _safe_add(target: Set[str], candidate: str):
    """Add candidate if it parses as a PEP 440 version."""
    try:
        Version(candidate)
    except InvalidVersion:
        return
    target.add(candidate)


def _fixed_from_ranges(ranges: List[dict]) -> Set[str]:
    out: Set[str] = set()
    for r in ranges:
        for ev in r.get("events", []):
            if "fixed" in ev:
                _safe_add(out, ev["fixed"])
    return out


def _query_osv(pkg: str, ver: str) -> List[str]:
    body = {"package": {"name": pkg, "ecosystem": "PyPI"}, "version": ver}
    r = requests.post(OSV_QUERY, json=body, timeout=10)
    if r.status_code != 200:
        return []
    fixes: Set[str] = set()
    for v in r.json().get("vulns", []):
        for aff in v.get("affected", []):
            fixes.update(_fixed_from_ranges(aff.get("ranges", [])))
    return sorted(fixes, key=Version)


def build_fix_matrix(findings: List[Finding]) -> List[Dict]:
    matrix = []
    for f in findings:
        if not f.vulns:
            continue
        versions = _query_osv(f.package, f.current)
        matrix.append(
            {
                "package": f.package,
                "current": f.current,
                "dependencyType": "DIRECT" if f.is_direct else "TRANSITIVE",
                "fixes_available": [{"version": v} for v in versions],
            }
        )
        time.sleep(0.05)
    return matrix

if __name__ == "__main__":
    import sys
    from deps_graph import parse_requirements, build_graph
    from depsdev_client import scan

    reqs = parse_requirements(sys.argv[1] if len(sys.argv) > 1 else "requirements.txt")
    findings = scan(build_graph(reqs), progress=False).findings
    print(json.dumps(build_fix_matrix(findings), indent=2))
