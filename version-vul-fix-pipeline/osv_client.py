"""osv_client.py  – batch query OSV API."""

from __future__ import annotations
import sys, requests, networkx as nx
from typing import List
from autoheal_types import AffectedRange, Finding, Vuln, VulnReport

OSV = "https://api.osv.dev/v1/querybatch"


def _chunk(it, size):
    buf = []
    for item in it:
        buf.append(item)
        if len(buf) == size:
            yield buf
            buf = []
    if buf:
        yield buf


def _to_range(r):
    ev = r.get("events", [])
    return AffectedRange(
        introduced=ev[0].get("introduced") if ev else None,
        fixed=ev[-1].get("fixed") if ev else None,
        type=r["type"],
    )


def scan(graph: nx.DiGraph, *, progress=True) -> VulnReport:
    nodes = list(graph.nodes)
    queries = [{"package": {"name": n[0], "ecosystem": "PyPI"}, "version": n[1]} for n in nodes]
    iterator = _chunk(range(len(queries)), 1000)
    if progress and sys.stderr.isatty():
        try:
            from tqdm import tqdm
            iterator = tqdm(iterator, desc="OSV", unit="pkg")
        except ModuleNotFoundError:
            pass

    findings: List[Finding] = []
    for start_chunk in iterator:
        chunk = queries[start_chunk : start_chunk + 1000]
        res = requests.post(OSV, json={"queries": chunk}, timeout=30).json()["results"]
        for q, r in zip(chunk, res):
            pkg, ver = q["package"]["name"], q["version"]
            is_direct = graph.nodes[(pkg, ver)]["is_direct"]
            vulns = [
                Vuln(
                    id=v["id"],
                    summary=v.get("summary", ""),
                    details_url=f"https://osv.dev/{v['id']}",
                    severity=max(
                        (float(s["score"]) for s in v.get("severity", []) if s["type"] == "CVSS_V3"),
                        default=None,
                    ),
                    ranges=[_to_range(rr) for rr in v.get("ranges", [])],
                )
                for v in r.get("vulns", [])
            ]
            findings.append(Finding(package=pkg, current=ver, is_direct=is_direct, vulns=vulns))
    return VulnReport(findings=findings, graph=graph)
