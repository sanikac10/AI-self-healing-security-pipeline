"""cli.py
============================================================
Command‑line interface glueing together the **types**, **deps_graph**,
and **osv_client** modules.

Usage
-----
::

    # Basic scan – prints vulnerable packages succinctly
    python cli.py path/to/requirements.txt

    # Generate a JSON report for CI pipelines
    python cli.py requirements.txt --json vuln_report.json

The CLI is intentionally minimal; integrate into your own tool or wrap
with a FastAPI service for a richer UI.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from deps_graph import build_graph, parse_requirements
from osv_client import scan

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
LOG = logging.getLogger("autoheal.cli")


# ------------------------------------------------------------------------
# Pretty helpers (no external deps except colorama when available)
# ------------------------------------------------------------------------

try:
    from colorama import Fore, Style, init as _init_colorama

    _init_colorama()
    COLOR = True
except ModuleNotFoundError:
    COLOR = False


def _bright(txt: str, colour: str = ""):
    if not COLOR:
        return txt
    return f"{colour}{txt}{Style.RESET_ALL}"


# ------------------------------------------------------------------------
# Main entry‑point
# ------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Scan pinned PyPI requirements for known vulnerabilities (OSV)")
    p.add_argument("requirements", help="Path to *pinned* requirements.txt")
    p.add_argument("--json", dest="json_out", help="Save full VulnReport as JSON")
    p.add_argument("--no‑progress", action="store_true", help="Disable tqdm progress bar")
    args = p.parse_args(argv)

    try:
        reqs = parse_requirements(args.requirements)
        LOG.info("Parsed %d direct dependencies", len(reqs))

        graph = build_graph(reqs)
        LOG.info("Resolved %d total packages (%d edges)", len(graph.nodes), len(graph.edges))

        report = scan(graph, progress=not args.no_progress)
        vulnerable = [f for f in report.findings if f.vulns]
        LOG.info("%d / %d packages have known vulns", len(vulnerable), len(report.findings))

        # -----------------------------------------------------------------
        # Output
        # -----------------------------------------------------------------
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(report, default=lambda o: o.__dict__, indent=2))
            print(f"Saved JSON report ➜ {args.json_out}")
        else:
            for f in vulnerable:
                worst = max((v.severity or 0.0) for v in f.vulns)
                direct_tag = _bright("DIRECT", Fore.GREEN) if f.is_direct else "transitive"
                print(f"- {f.package}=={f.current}  [{direct_tag}]  (CVSS ≤ {worst:.1f})")
                for v in f.vulns:
                    print(f"    • {v.id}  →  {v.details_url}")
    except Exception as exc:
        LOG.error(exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
