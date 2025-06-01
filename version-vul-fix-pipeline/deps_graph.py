"""deps_graph.py  (v1.4)
Build dependency graph with full transitive coverage.
Logic:
1. Try deps.dev `?include=DEPENDENCIES` (version‑level).
2. If deps.dev returns *no* dependencies, fall back to PyPI
   `requires_dist` metadata for that release.
"""
from __future__ import annotations
import json, logging, os, re
from functools import lru_cache
from pathlib import Path
from typing import List, Tuple, Set

import networkx as nx
import requests
from packaging.requirements import Requirement
from packaging.markers import default_environment
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet

from autoheal_types import ReqLine

DEPSDEV = "https://api.deps.dev/v3alpha"
CACHE   = Path(os.getenv("AUTOHEAL_CACHE", "~/.autoheal_cache")).expanduser()
CACHE.mkdir(parents=True, exist_ok=True)
PYPI_JSON = "https://pypi.org/pypi/{pkg}/json"
PYPI_RELEASE = "https://pypi.org/pypi/{pkg}/{ver}/json"
LOG = logging.getLogger(__name__)

# ── helper: resolve loose spec to newest satisfying version ─────────────
@lru_cache(maxsize=None)
def _resolve_latest(pkg: str, spec: str) -> str:
    data = requests.get(PYPI_JSON.format(pkg=pkg), timeout=10).json()
    vers = sorted((Version(v) for v in data["releases"]), reverse=True)
    for v in vers:
        if v in SpecifierSet(spec):
            return str(v)
    raise ValueError(f"{pkg}: no version satisfies {spec}")

# ── cache helpers for deps.dev ──────────────────────────────────────────

def _cache(pkg, ver): return CACHE / f"{pkg}=={ver}.json"

def _read(p):
    if p.exists():
        try:
            return json.loads(p.read_text())
        except json.JSONDecodeError:
            return None
    return None

def _write(p, o):
    try:
        p.write_text(json.dumps(o))
    except OSError:
        pass

@lru_cache(maxsize=None)
def _fetch_ver(pkg: str, ver: str) -> dict:
    url = f"{DEPSDEV}/systems/PYPI/packages/{pkg}/versions/{ver}?include=DEPENDENCIES"
    r = requests.get(url, timeout=10)
    if r.status_code == 404:
        return {}
    r.raise_for_status()
    return r.json()

def _payload(pkg, ver):
    p = _cache(pkg, ver)
    obj = _read(p)
    if obj is None:
        obj = _fetch_ver(pkg, ver)
        _write(p, obj)
    return obj

# ── fallback: requires_dist from PyPI release metadata ─────────────────
@lru_cache(maxsize=None)
def _requires_dist(pkg: str, ver: str):
    try:
        data = requests.get(PYPI_RELEASE.format(pkg=pkg, ver=ver), timeout=10).json()
        items = data.get("info", {}).get("requires_dist") or []
    except Exception:
        return []
    deps = []
    for item in items:
        token = item.split(";", 1)[0].strip()  # drop env marker
        try:
            req = Requirement(token)
            name = req.name.split("[",1)[0].lower()
            spec = str(req.specifier) if req.specifier else ">=0"
            deps.append((name, spec))
        except Exception:
            continue
    return deps

# ── req parsing ────────────────────────────────────────────────────────

def parse_requirements(path) -> List[ReqLine]:
    path = Path(path)
    parsed = []
    rx = re.compile(r"^\s*([^#\s].*?)\s*(?:#.*)?$")
    for ln, raw in enumerate(path.open(), 1):
        m = rx.match(raw)
        if not m:
            continue
        token = m.group(1)
        req = Requirement(token)
        if req.marker and not req.marker.evaluate(default_environment()):
            continue
        name = req.name.split("[",1)[0].lower()
        eq = [s for s in req.specifier if s.operator == "=="]
        if eq:
            ver = eq[0].version
        else:
            spec = str(req.specifier) or ">=0"
            ver  = _resolve_latest(name, spec)
            LOG.info("[line %d] %s %s → %s", ln, name, spec, ver)
        try:
            Version(ver)
        except InvalidVersion as e:
            raise ValueError(f"[line {ln}] bad version {ver}: {e}")
        parsed.append(ReqLine(raw=token.strip(), name=name, version=ver))
    if not parsed:
        raise ValueError("empty requirements")
    return parsed

# ── graph builder ──────────────────────────────────────────────────────

def build_graph(reqs: List[ReqLine]) -> nx.DiGraph:
    g = nx.DiGraph()
    frontier: List[Tuple[str,str,int]] = []
    visited:  Set[Tuple[str,str]] = set()

    for r in reqs:
        g.add_node((r.name, r.version), is_direct=True, depth=1)
        frontier.append((r.name, r.version, 1))

    while frontier:
        pkg, ver, depth = frontier.pop()
        if (pkg, ver) in visited:
            continue
        visited.add((pkg, ver))

        deps = _payload(pkg, ver).get("dependencies", [])
        if not deps:
            for name, spec in _requires_dist(pkg, ver):
                try:
                    dver = _resolve_latest(name, spec)
                except Exception:
                    continue
                g.add_node((name, dver), is_direct=False, depth=depth+1)
                g.add_edge((pkg, ver), (name, dver))
                frontier.append((name, dver, depth+1))
            continue

        for dep in deps:
            dname = dep["package"]["name"].lower()
            dver  = dep.get("version")
            if not dver:
                spec = dep.get("versionRequirement") or ">=0"
                try:
                    dver = _resolve_latest(dname, spec)
                except Exception:
                    LOG.warning("skip %s %s", dname, spec)
                    continue
            g.add_node((dname, dver), is_direct=False, depth=depth+1)
            g.add_edge((pkg, ver), (dname, dver))
            frontier.append((dname, dver, depth+1))

    return g
