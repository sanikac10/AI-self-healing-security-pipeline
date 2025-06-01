"""cli.py – end-to-end scanner with optional fixes output."""
from __future__ import annotations
import argparse, json, logging, sys
from pathlib import Path

from deps_graph import parse_requirements, build_graph
from depsdev_client import scan
from candidates import build_candidate_matrix
from fix_matrix import build_fix_matrix
from cli_patch import apply_fixes

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
LOG = logging.getLogger("autoheal.cli")

def main(argv=None):
    p = argparse.ArgumentParser("autoheal scan")
    p.add_argument("requirements")
    p.add_argument("--json",      dest="json_out")
    p.add_argument("--candidates", dest="cand_out")
    p.add_argument("--fixes",     dest="fix_out")
    p.add_argument("--no-progress", action="store_true")
    p.add_argument("--auto-patch", action="store_true", help="Apply fixes after generating --fixes")
    args = p.parse_args(argv)

    reqs  = parse_requirements(args.requirements)
    graph = build_graph(reqs)
    report = scan(graph, progress=not args.no_progress)
    vulns = [f for f in report.findings if f.vulns]

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, default=lambda o: o.__dict__, indent=2))
    if args.cand_out:
        Path(args.cand_out).write_text(json.dumps(build_candidate_matrix(report.findings), indent=2))
    if args.fix_out:
        Path(args.fix_out).write_text(json.dumps(build_fix_matrix(report.findings), indent=2))
    if args.auto_patch:
        apply_fixes(args.fix_out, args.requirements)


    for f in vulns:
        worst = max((v.severity or 0.0) for v in f.vulns)
        tag = "DIRECT" if f.is_direct else "TRANSITIVE"
        print(f"- {f.package}=={f.current} [{tag}] (CVSS ≤ {worst:.1f})")
        for v in f.vulns:
            print(f"    • {v.id} → {v.details_url}")


if __name__ == "__main__":
    main()
