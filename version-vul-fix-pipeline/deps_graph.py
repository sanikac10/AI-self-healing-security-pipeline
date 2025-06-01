"""deps_graph.py
============================================================
Dependency graph builder for pinned *PyPI* requirements.txt files.

This module performs two tasks:
1.  `parse_requirements()` – robustly parses and validates a *pinned*
    requirements file, returning a list of `ReqLine` objects.
2.  `build_graph()` – calls the **deps.dev** public API to expand
    direct requirements into a fully‑resolved *transitive* graph.

Design notes
------------
* No package installation is performed (safer than running `pip`).
* Responses are cached on disk *and* memoised in‑process to stay well
  below deps.dev rate‑limits (10 req/s unauthenticated).
* The resulting graph uses a tuple `(name, version)` as the node key to
  avoid duplicate names across different version pins.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import List, Tuple, Set

import networkx as nx
import requests
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.version import Version, InvalidVersion

from types import ReqLine

# ------------------------------------------------------------------------
# Module‑level constants
# ------------------------------------------------------------------------

DEPSDEV_BASE = "https://api.deps.dev/v3alpha"
CACHE_DIR = Path(os.getenv("AUTOHEAL_CACHE", "~/.autoheal_cache")).expanduser()
CACHE_DIR.mkdir(parents=True, exist_ok=True)

_LOG = logging.getLogger(__name__)

# ------------------------------------------------------------------------
# Public helpers
# ------------------------------------------------------------------------


def parse_requirements(path: str | os.PathLike) -> List[ReqLine]:
    """Return a list of *pinned* requirements from the given file.

    Raises
    ------
    ValueError
        If **any** requirement is not pinned with the `==` operator or
        the version string fails PEP 440 validation.
    """

    reqs: List[ReqLine] = []
    line_rx = re.compile(r"^\s*([^#\s].*?)\s*(?:#.*)?$")
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)

    with path.open(encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            m = line_rx.match(raw)
            if not m:
                continue  # blank line or comment
            token = m.group(1)

            # Ignore editable installs & direct VCS refs for now.
            if token.startswith("-e ") or token.startswith("git+"):
                _LOG.warning("[line %d] skipping VCS/editable requirement: %s", lineno, token)
                continue

            try:
                r = Requirement(token)
            except Exception as exc:  # pragma: no cover – rare
                raise ValueError(f"[line {lineno}] cannot parse: {token}\n→ {exc}") from exc

            # Evaluate environment marker (e.g. ; python_version<'3.9')
            if r.marker and not r.marker.evaluate(default_environment()):
                continue

            name = r.name.split("[", 1)[0].lower()  # strip extras

            # Enforce pinning (==)
            eq_pins = [s for s in r.specifier if s.operator == "=="]
            if not eq_pins:
                raise ValueError(
                    f"[line {lineno}] '{name}' is not pinned – autoheal scans only '==X.Y.Z' pins.")
            version = eq_pins[0].version
            try:
                Version(version)
            except InvalidVersion as exc:
                raise ValueError(f"[line {lineno}] '{name}' has invalid version '{version}': {exc}") from exc

            reqs.append(ReqLine(raw=token.strip(), name=name, version=version))

    if not reqs:
        raise ValueError("No valid pinned requirements found – aborting.")
    return reqs


# ------------------------------------------------------------------------
# deps.dev fetcher with disk‑cache and retry
# ------------------------------------------------------------------------


def _cache_file(name: str, version: str) -> Path:
    return CACHE_DIR / f"{name.lower()}=={version}.json"


def _read_cache(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text()) if path.exists() else None
    except json.JSONDecodeError:
        return None


def _write_cache(path: Path, payload: dict) -> None:
    try:
        path.write_text(json.dumps(payload))
    except OSError:
        pass  # non‑fatal – cache is best‑effort


@lru_cache(maxsize=None)
def _fetch_remote(name: str, version: str) -> dict:
    url = f"{DEPSDEV_BASE}/systems/PyPI/packages/{name}/versions/{version}:dependencies"
    resp = requests.get(url, timeout=10)
    if resp.status_code == 404:
        return {}
    resp.raise_for_status()
    return resp.json()


def _get_deps_payload(name: str, version: str) -> dict:
    cache_path = _cache_file(name, version)
    cached = _read_cache(cache_path)
    if cached is not None:
        return cached

    retries, delay = 3, 0.5
    for n in range(retries):
        try:
            payload = _fetch_remote(name, version)
            _write_cache(cache_path, payload)
            return payload
        except requests.RequestException as exc:
            if n == retries - 1:
                raise
            _LOG.warning("deps.dev fetch failed (%s==%s) – retry %d/%d", name, version, n + 1, retries)
            time.sleep(delay)
            delay *= 2
    return {}


# ------------------------------------------------------------------------
# Graph builder
# ------------------------------------------------------------------------

def build_graph(reqs: List[ReqLine]) -> nx.DiGraph:
    """Return a fully‑resolved dependency graph for *pinned* requirements.

    Notes
    -----
    * Nodes are `(name, version)` tuples (both lowercase).
    * Node attrs:
        • `is_direct` (bool)
        • `depth`      (int)  – 1 for direct, >=2 for transitives
    """

    g: nx.DiGraph = nx.DiGraph()
    frontier: List[Tuple[str, str, int]] = []
    visited: Set[Tuple[str, str]] = set()

    # Seed with direct requirements
    for r in reqs:
        g.add_node((r.name, r.version), is_direct=True, depth=1)
        frontier.append((r.name, r.version, 1))

    while frontier:
        pkg, ver, depth = frontier.pop()
        if (pkg, ver) in visited:
            continue
        visited.add((pkg, ver))

        payload = _get_deps_payload(pkg, ver)
        for dep in payload.get("dependencies", []):
            dep_name = dep["package"]["name"].lower()
            dep_ver = dep["version"] or ""  # can be empty for optional markers
            if not dep_ver:
                continue  # skip unpinned / optional requirements

            g.add_node((dep_name, dep_ver), is_direct=False, depth=depth + 1)
            g.add_edge((pkg, ver), (dep_name, dep_ver))
            frontier.append((dep_name, dep_ver, depth + 1))

    return g
