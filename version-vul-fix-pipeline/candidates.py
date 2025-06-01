"""candidates.py
============================================================
Convert Vulnerability findings into upgrade-candidate matrix.
"""

from typing import List, Dict
from packaging.version import Version
from autoheal_types import Finding, AffectedRange


def _sorted_unique(vset):
    return sorted(vset, key=Version)


def _collect_fixed_versions(ranges: List[AffectedRange], current: str):
    out = set()
    cur = Version(current)
    for r in ranges:
        if r.fixed:
            out.add(r.fixed)
        elif r.introduced and Version(r.introduced) > cur:
            out.add(r.introduced)
    return out


def build_candidate_matrix(findings: List[Finding]) -> List[Dict]:
    matrix = []
    for f in findings:
        if not f.vulns:
            continue
        fixed = set()
        for v in f.vulns:
            fixed.update(_collect_fixed_versions(v.ranges, f.current))
        matrix.append(
            {
                "package": f.package,
                "current": f.current,
                "dependencyType": "DIRECT" if f.is_direct else "TRANSITIVE",
                "candidates": [{"version": v} for v in _sorted_unique(fixed)],
            }
        )
    return matrix


if __name__ == "__main__":
    import sys, json
    from deps_graph import parse_requirements, build_graph
    from depsdev_client import scan

    req = parse_requirements(sys.argv[1] if len(sys.argv) > 1 else "requirements.txt")
    findings = scan(build_graph(req), progress=False).findings
    print(json.dumps(build_candidate_matrix(findings), indent=2))
