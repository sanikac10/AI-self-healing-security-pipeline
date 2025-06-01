"""extractor_graph.py  (final fix)
Robustly parse stdout from requirements_extractor.py even if it prints
warnings and blank lines. We search from the *beginning* for first JSON
char, then json.loads the substring. This avoids IndexError/empty-line
problems.
"""
from __future__ import annotations
import json, subprocess, sys
from pathlib import Path
from typing import List, Tuple
import networkx as nx

_EXTRACTOR = Path(__file__).with_name("requirements_extractor.py")


def _run_extractor(req_path: str | Path) -> dict:
    cmd = [sys.executable, str(_EXTRACTOR), str(req_path)]
    out = subprocess.check_output(cmd, text=True)
    # find first '{' or '[' (JSON start)
    pos_brace = out.find("{")
    pos_brack = out.find("[")
    start = min([p for p in (pos_brace, pos_brack) if p != -1], default=-1)
    if start == -1:
        raise RuntimeError("Extractor stdout did not contain JSON")
    return json.loads(out[start:])


def build_graph_via_extractor(req_path: str | Path) -> nx.DiGraph:
    blob = _run_extractor(req_path)
    node_strings: List[str] = blob["nodes"]
    edge_strings: List[Tuple[str, str]] = [tuple(e) for e in blob["edges"]]

    direct_pkgs = {
        line.split("==", 1)[0].strip().lower()
        for line in Path(req_path).read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    }

    g = nx.DiGraph()
    for s in node_strings:
        pkg, _, ver = s.partition("==")
        g.add_node((pkg.lower(), ver or "unknown"), is_direct=pkg.lower() in direct_pkgs)

    for u, v in edge_strings:
        upkg, _, uver = u.partition("==")
        vpkg, _, vver = v.partition("==")
        g.add_edge((upkg.lower(), uver or "unknown"), (vpkg.lower(), vver or "unknown"))

    roots = [(p, v) for p, v in g.nodes if g.nodes[(p, v)]["is_direct"]]
    for root in roots:
        for node, dist in nx.single_source_shortest_path_length(g, root).items():
            g.nodes[node]["depth"] = dist + 1
    return g