"""cli.py – use either internal resolver or external requirements_extractor.

New flag:
    --use-extractor   → build graph via requirements_extractor.py
"""
from __future__ import annotations
import argparse, json, logging, sys
from pathlib import Path

from deps_graph import parse_requirements, build_graph
from extractor_graph import build_graph_via_extractor
from depsdev_client import scan
from candidates import build_candidate_matrix
from fix_matrix import build_fix_matrix

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
LOG = logging.getLogger("autoheal.cli")

try:
    from colorama import Fore, Style, init as _init_color
    _init_color(); COLOR = True
except ModuleNotFoundError:
    COLOR = False

def _bright(t, c=""): return f"{c}{t}{Style.RESET_ALL}" if COLOR else t


def main(argv=None):
    p = argparse.ArgumentParser("autoheal scan")
    p.add_argument("requirements")
    p.add_argument("--use-extractor", action="store_true",
                   help="build dependency graph via requirements_extractor.py")
    p.add_argument("--json", dest="json_out")
    p.add_argument("--candidates", dest="cand_out")
    p.add_argument("--fixes", dest="fix_out")
    p.add_argument("--dep-tree", dest="tree_out")
    p.add_argument("--no-progress", action="store_true")
    args = p.parse_args(argv)

    reqs = parse_requirements(args.requirements)
    if args.use_extractor:
        graph = build_graph_via_extractor(args.requirements)
    else:
        graph = build_graph(reqs)
    LOG.info("Resolved %d total packages (%d edges)", len(graph.nodes), len(graph.edges))

    report = scan(graph, progress=not args.no_progress)
    vulns = [f for f in report.findings if f.vulns]

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, default=lambda o: o.__dict__, indent=2))
    if args.cand_out:
        Path(args.cand_out).write_text(json.dumps(build_candidate_matrix(report.findings), indent=2))
    if args.fix_out:
        Path(args.fix_out).write_text(json.dumps(build_fix_matrix(report.findings), indent=2))
    if args.tree_out:
        nodes = [
            {
                "package": p,
                "version": v,
                "is_direct": graph.nodes[(p,v)]["is_direct"],
                "depth": graph.nodes[(p,v)].get("depth", 1),
            }
            for p,v in graph.nodes
        ]
        edges = [{"from": u, "to": v} for u, v in graph.edges]
        Path(args.tree_out).write_text(json.dumps({"nodes": nodes, "edges": edges}, indent=2))

    if not any([args.json_out, args.cand_out, args.fix_out, args.tree_out]):
        for f in vulns:
            worst = max((v.severity or 0.0) for v in f.vulns)
            tag = _bright("DIRECT", Fore.GREEN) if f.is_direct else "TRANSITIVE"
            print(f"- {f.package}=={f.current} [{tag}] (CVSS ≤ {worst:.1f})")
            for v in f.vulns:
                print(f"    • {v.id} → {v.details_url}")


if __name__ == "__main__":
    main()
