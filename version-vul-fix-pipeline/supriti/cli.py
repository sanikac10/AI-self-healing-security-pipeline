from fixer import FixSelector
from packaging.version import parse as parse_version
import json
from patcher import patch_requirements, run_tests

def extract_candidates(finding):
    current_ver = parse_version(finding["current"])
    fixed_versions = set()

    for vuln in finding.get("vulns", []):
        for r in vuln.get("ranges", []):
            if r.get("type") == "SEMVER" and "fixed" in r:
                fixed_ver = parse_version(r["fixed"])
                if fixed_ver > current_ver:
                    fixed_versions.add(str(fixed_ver))

    return sorted(list(fixed_versions), key=lambda v: parse_version(v))

def main():
    with open("findings.json", "r") as f:
        data = json.load(f)

    fixer = FixSelector()
    upgrade_map = {}

    for finding in data["findings"]:
        if finding.get("vulns"):
            candidates = [{"version": v} for v in extract_candidates(finding)]
            input_data = {
                "package": finding["package"],
                "current": finding["current"],
                "candidates": candidates
            }
            result = fixer.choose_fix(input_data, use_llm=False)
            upgrade_map[result["package"]] = result["chosen_version"]

    if upgrade_map:
        print("Applying patches:", upgrade_map)
        patch_requirements("requirements.txt", upgrade_map)

        if run_tests("requirements.txt"):
            print("All tests passed.")
        else:
            print("Tests failed after patch. Manual fix required.")
    else:
        print("No upgrades necessary.")

    

if __name__ == "__main__":
    main()
