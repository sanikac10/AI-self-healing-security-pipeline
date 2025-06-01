"""depsdev_client.py  (v2.1)
Fetch vulnerabilities from deps.dev, INCLUDING aliases.
"""
from __future__ import annotations
import json, logging, os, sys, time
from functools import lru_cache
from pathlib import Path
from typing import List

import networkx as nx
import requests
from autoheal_types import AffectedRange, Vuln, Finding, VulnReport

DEPSDEV_BASE = "https://api.deps.dev/v3alpha"
CACHE_DIR = Path(os.getenv("AUTOHEAL_CACHE", "~/.autoheal_cache")).expanduser()
CACHE_DIR.mkdir(parents=True, exist_ok=True)
LOG = logging.getLogger(__name__)


# ── simple disk-cache helpers ───────────────────────────────────────────
def _read_cache(p: Path):
    if p.exists():
        try: return json.loads(p.read_text())
        except json.JSONDecodeError: return None
    return None

def _write_cache(p: Path, obj: dict):
    try: p.write_text(json.dumps(obj))
    except OSError: pass

def _ver_cache(pkg, ver): return CACHE_DIR / f"{pkg}=={ver}.ver.json"
def _adv_cache(aid):     return CACHE_DIR / f"adv_{aid}.json"


# ── deps.dev fetch helpers ──────────────────────────────────────────────
def _fetch_version(pkg, ver):
    url = f"{DEPSDEV_BASE}/systems/PYPI/packages/{pkg}/versions/{ver}?include=VULNERABILITIES"
    r = requests.get(url, timeout=10)
    if r.status_code == 404: return {}
    r.raise_for_status(); return r.json()

@lru_cache(maxsize=None)
def _fetch_adv_remote(aid):
    r = requests.get(f"{DEPSDEV_BASE}/advisories/{aid}", timeout=10)
    if r.status_code == 404: return {}
    r.raise_for_status(); return r.json()

def _get_ver(pkg, ver):
    p = _ver_cache(pkg, ver)
    obj = _read_cache(p)
    if obj is None:
        obj = _fetch_version(pkg, ver)
        _write_cache(p, obj)
    return obj

def _get_adv(aid):
    p = _adv_cache(aid)
    obj = _read_cache(p)
    if obj is None:
        obj = _fetch_adv_remote(aid)
        _write_cache(p, obj)
    return obj


# ── public scan() ───────────────────────────────────────────────────────
def scan(graph: nx.DiGraph, *, throttle: float = 0.05, progress: bool = True) -> VulnReport:
    nodes = list(graph.nodes)
    iterator = enumerate(nodes, 1)
    if progress and sys.stderr.isatty():
        try:
            from tqdm import tqdm
            iterator = tqdm(iterator, total=len(nodes), desc="deps.dev", unit="pkg")
        except ModuleNotFoundError: pass

    findings: List[Finding] = []
    for _, (pkg, ver) in iterator:
        is_direct = graph.nodes[(pkg, ver)]["is_direct"]
        ver_json  = _get_ver(pkg, ver)
        ids = [k["id"] for k in ver_json.get("advisoryKeys", [])]

        vulns: List[Vuln] = []
        for aid in ids:
            adv = _get_adv(aid)
            if not adv: continue
            cvss = None
            for s in adv.get("severity", []):
                if s.get("type") == "CVSS_V3":
                    try: cvss = max(cvss or 0.0, float(s["score"]))
                    except (ValueError, TypeError): pass
            ranges = [
                AffectedRange(
                    introduced=(ev[0].get("introduced") if (ev := r.get("events")) else None),
                    fixed=(ev[-1].get("fixed") if ev else None),
                    type=r["type"],
                )
                for r in adv.get("affectedRanges", [])
            ]
            vulns.append(
                Vuln(
                    id       = adv.get("id", aid),
                    summary  = adv.get("summary", ""),
                    details_url = f"https://deps.dev/advisory/{adv.get('id', aid)}",
                    severity = cvss,
                    ranges   = ranges,
                    aliases  = adv.get("aliases", []),
                )
            )
        findings.append(Finding(package=pkg, current=ver, is_direct=is_direct, vulns=vulns))
        time.sleep(throttle)
    return VulnReport(findings=findings, graph=graph)
