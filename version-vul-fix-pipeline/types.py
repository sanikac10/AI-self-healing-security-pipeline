"""types.py
============================================================
Shared dataclass definitions for the Autoheal pipeline.

These *plain‑old data* objects travel between the parser,
resolver, vulnerability scanner, and fixer stages without
any business logic attached – making each module completely
black‑box testable and serialisable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import networkx as nx

__all__ = [
    "ReqLine",
    "AffectedRange",
    "Vuln",
    "Finding",
    "VulnReport",
]


# ------------------------------------------------------------------------
# 📦 Requirements model (direct user input)
# ------------------------------------------------------------------------

@dataclass(frozen=True)
class ReqLine:
    """A *single line* from requirements.txt after sanitising.

    Attributes
    ----------
    raw : str
        The original text (for later diffing / rewriting).
    name : str
        Canonicalised PyPI name (PEP 503 normalised – lower‑case).
    version : str
        PEP 440‐compliant *pinned* version extracted from "==".
    is_direct : bool, default=True
        Always *True* at parse time; transitive deps override this to
        False inside the resolver.
    """

    raw: str
    name: str
    version: str
    is_direct: bool = True


# ------------------------------------------------------------------------
# 🛡️ Vulnerability domain model (OSV schema distilled)
# ------------------------------------------------------------------------

@dataclass(frozen=True)
class AffectedRange:
    introduced: Optional[str]  # first vulnerable version (or None)
    fixed: Optional[str]       # first *non‑vulnerable* version (or None)
    type: str                  # "SEMVER" | "ECOSYSTEM" | "GIT" …


@dataclass(frozen=True)
class Vuln:
    id: str                    # OSV‑ID (often == CVE‑ID)
    summary: str
    details_url: str           # canonical landing page on osv.dev
    severity: Optional[float]  # max CVSS v3 score if present
    ranges: List[AffectedRange]


@dataclass(frozen=True)
class Finding:
    package: str               # PyPI name
    current: str               # version string currently in use
    is_direct: bool            # True if top‑level in requirements.txt
    vulns: List[Vuln]          # empty list ⇒ no known issues


@dataclass(frozen=True)
class VulnReport:
    """Aggregate object returned by osv_client.scan()."""

    findings: List[Finding]
    graph: nx.DiGraph          # full dependency graph with depth attrs
