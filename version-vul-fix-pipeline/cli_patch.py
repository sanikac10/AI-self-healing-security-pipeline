import json
from fixer import FixSelector
from patcher import patch_requirements, run_tests
from packaging.version import parse as parse_version

def extract_candidates(finding):
    current_ver = parse_version(finding["current"])
    fixed_versions = {
        str(parse_version(f["version"]))
        for f in finding.get("fixes_available", [])
        if parse_version(f["version"]) > current_ver
    }
    return sorted(list(fixed_versions), key=parse_version)

def apply_fixes(fixes_path: str, requirements_path: str = "requirements.txt"):
    with open(fixes_path, "r") as f:
        findings = json.load(f)

    fixer = FixSelector()

    for finding in findings:
        candidates = [{"version": v} for v in extract_candidates(finding)]
        if not candidates:
            continue

        input_data = {
            "package": finding["package"],
            "current": finding["current"],
            "candidates": candidates
        }

        print(f"\n📦 Attempting to patch: {input_data['package']}")

        result = fixer.choose_fix(input_data, use_llm=False)
        single_patch = {result["package"]: result["chosen_version"]}

        patch_requirements(requirements_path, single_patch)

        if run_tests(requirements_path):
            print(f"✅ Patch succeeded for {result['package']}")
        else:
            print(f"❌ Patch failed for {result['package']}. Reverting...")
            # Optionally undo the patch by resetting to previous state
            return


