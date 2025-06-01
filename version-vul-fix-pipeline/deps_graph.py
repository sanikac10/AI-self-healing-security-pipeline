"""deps_graph.py
============================================================
Parses requirements.txt (pinned or loose) and builds a full
dependency graph via deps.dev.
"""

from __future__ import annotations
import json, logging, os, re, time
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

DEPSDEV_BASE = "https://api.deps.dev/v3alpha"
CACHE_DIR = Path(os.getenv("AUTOHEAL_CACHE", "~/.autoheal_cache")).expanduser()
CACHE_DIR.mkdir(parents=True, exist_ok=True)
PYPI_JSON = "https://pypi.org/pypi/{pkg}/json"
_LOG = logging.getLogger(__name__)


# ── helper: resolve loose spec to latest satisfying version ─────────────
@lru_cache(maxsize=None)
def _resolve_latest_match(pkg: str, spec: str) -> str:
    data = requests.get(PYPI_JSON.format(pkg=pkg), timeout=10).json()
    all_versions = [Version(v) for v in data["releases"]]
    matches = sorted([v for v in all_versions if v in SpecifierSet(spec)],
                     reverse=True)
    if not matches:
        raise ValueError(f"{pkg}: no PyPI version satisfies '{spec}'")
    return str(matches[0])


# ── disk-cache helpers for deps.dev responses ───────────────────────────
def _cache_file(name: str, version: str) -> Path:
    return CACHE_DIR / f"{name.lower()}=={version}.json"


def _read_cache(path: Path):
    try:
        return json.loads(path.read_text()) if path.exists() else None
    except json.JSONDecodeError:
        return None


def _write_cache(path: Path, obj: dict):
    try:
        path.write_text(json.dumps(obj))
    except OSError:
        pass


@lru_cache(maxsize=None)
def _fetch_remote(name: str, version: str) -> dict:
    url = f"{DEPSDEV_BASE}/systems/PYPI/packages/{name}/versions/{version}:dependencies"
    r = requests.get(url, timeout=10)
    if r.status_code == 404:
        return {}
    r.raise_for_status()
    return r.json()


def _get_payload(name: str, version: str) -> dict:
    path = _cache_file(name, version)
    cached = _read_cache(path)
    if cached is not None:
        return cached
    data = _fetch_remote(name, version)
    _write_cache(path, data)
    return data


# ── public helpers ──────────────────────────────────────────────────────
def parse_requirements(path: str | os.PathLike) -> List[ReqLine]:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)

    parsed: List[ReqLine] = []
    line_rx = re.compile(r"^\s*([^#\s].*?)\s*(?:#.*)?$")
    for lineno, raw in enumerate(path.open(encoding="utf-8"), 1):
        m = line_rx.match(raw)
        if not m:
            continue
        token = m.group(1)
        if token.startswith("-e ") or token.startswith("git+"):
            _LOG.warning("[line %d] skipping VCS/editable: %s", lineno, token)
            continue
        req = Requirement(token)
        if req.marker and not req.marker.evaluate(default_environment()):
            continue

        name = req.name.split("[", 1)[0].lower()
        eq_pin = [s for s in req.specifier if s.operator == "=="]
        if eq_pin:
            version = eq_pin[0].version
        else:
            spec_text = str(req.specifier) if req.specifier else ">=0"
            version = _resolve_latest_match(name, spec_text)
            _LOG.info("[line %d] '%s %s' → %s", lineno, name, spec_text, version)
        try:
            Version(version)
        except InvalidVersion as exc:
            raise ValueError(f"[line {lineno}] invalid version '{version}': {exc}") from exc
        parsed.append(ReqLine(raw=token.strip(), name=name, version=version))
    if not parsed:
        raise ValueError("No valid requirements found.")
    return parsed


def build_graph(reqs: List[ReqLine]) -> nx.DiGraph:
    g: nx.DiGraph = nx.DiGraph()
    frontier: List[Tuple[str, str, int]] = []
    visited: Set[Tuple[str, str]] = set()
    for r in reqs:
        g.add_node((r.name, r.version), is_direct=True, depth=1)
        frontier.append((r.name, r.version, 1))

    while frontier:
        pkg, ver, depth = frontier.pop()
        if (pkg, ver) in visited:
            continue
        visited.add((pkg, ver))
        payload = _get_payload(pkg, ver)
        for dep in payload.get("dependencies", []):
            dname = dep["package"]["name"].lower()
            dver = dep["version"] or ""
            if not dver:
                continue
            g.add_node((dname, dver), is_direct=False, depth=depth + 1)
            g.add_edge((pkg, ver), (dname, dver))
            frontier.append((dname, dver, depth + 1))
    return g
