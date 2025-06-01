"""autoheal_types.py  (v1.1)
Shared dataclasses used across the pipeline.  Now includes `aliases`
inside `Vuln` so we can map to CVE IDs.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional
import networkx as nx


@dataclass(frozen=True)
class ReqLine:
    raw: str
    name: str
    version: str
    is_direct: bool = True


@dataclass(frozen=True)
class AffectedRange:
    introduced: Optional[str]
    fixed: Optional[str]
    type: str                     # "SEMVER" | "ECOSYSTEM" | "GIT" …


@dataclass(frozen=True)
class Vuln:
    id: str
    summary: str
    details_url: str
    severity: Optional[float]
    ranges: List[AffectedRange]
    aliases: List[str]            # e.g. ["CVE-2021-43818"]


@dataclass(frozen=True)
class Finding:
    package: str
    current: str
    is_direct: bool
    vulns: List[Vuln]


@dataclass(frozen=True)
class VulnReport:
    findings: List[Finding]
    graph: nx.DiGraph
