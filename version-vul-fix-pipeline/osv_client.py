"""osv_client.py
============================================================
Query the Open‑Source Vulnerability (OSV) API for every node in a
dependency graph and generate a `VulnReport`.

Only PyPI packages are supported in v1. The function `scan()` is the
public entry‑point – importable by a CLI, web service, or Jupyter
notebook.
"""

from __future__ import annotations

import logging
import sys
from typing import Iterable, List

import networkx as nx
import requests

from types import AffectedRange, Finding, Vuln, VulnReport

LOG = logging.getLogger(__name__)
OSV_BATCH_ENDPOINT = "https://api.osv.dev/v1/querybatch"

# ------------------------------------------------------------------------
# Helper utilities
# ------------------------------------------------------------------------

def _chunk(iterable: Iterable, size: int):
    buf = []
    for item in iterable:
        buf.append(item)
        if len(buf) == size:
            yield buf
            buf = []
    if buf:
        yield buf


def _to_range(obj: dict) -> AffectedRange:
    events = obj.get("events", [])
    introduced = events[0].get("introduced") if events else None
    fixed = events[-1].get("fixed") if events else None
    return AffectedRange(introduced=introduced, fixed=fixed, type=obj["type"])


# ------------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------------

def scan(graph: nx.DiGraph, progress: bool = True) -> VulnReport:
    """Return a `VulnReport` for every package‑version node in *graph*.

    Parameters
    ----------
    graph : nx.DiGraph
        Created by `deps_graph.build_graph()`; nodes are `(name, version)`.
    progress : bool, default=True
        Show a progress bar if *tqdm* is installed and stderr is a TTY.
    """

    nodes = list(graph.nodes)
    queries = [
        {
            "package": {"name": name, "ecosystem": "PyPI"},
            "version": ver,
        }
        for name, ver in nodes
    ]

    findings: List[Finding] = []

    # Lazy import tqdm only when useful
    iterator = range(0, len(queries), 1000)
    if progress and sys.stderr.isatty():
        try:
            from tqdm import tqdm

            iterator = tqdm(iterator, desc="OSV", unit="pkg")
        except ModuleNotFoundError:
            pass

    for start in iterator:
        chunk = queries[start : start + 1000]
        resp = requests.post(OSV_BATCH_ENDPOINT, json={"queries": chunk}, timeout=30)
        resp.raise_for_status()
        results = resp.json()["results"]

        for node_q, result in zip(chunk, results):
            pkg = node_q["package"]["name"].lower()
            ver = node_q["version"]
            is_direct = graph.nodes[(pkg, ver)].get("is_direct", False)

            vulns: List[Vuln] = []
            for osv in result.get("vulns", []):
                ranges = [_to_range(r) for r in osv.get("ranges", [])]
                cvss = None
                for sev in osv.get("severity", []):
                    if sev.get("type") == "CVSS_V3":
                        try:
                            score = float(sev["score"])
                            cvss = max(cvss or 0.0, score)
                        except (ValueError, TypeError):
                            pass
                vulns.append(
                    Vuln(
                        id=osv["id"],
                        summary=osv.get("summary", ""),
                        details_url=f"https://osv.dev/{osv['id']}",
                        severity=cvss,
                        ranges=ranges,
                    )
                )

            findings.append(
                Finding(package=pkg, current=ver, is_direct=is_direct, vulns=vulns)
            )

    return VulnReport(findings=findings, graph=graph)
