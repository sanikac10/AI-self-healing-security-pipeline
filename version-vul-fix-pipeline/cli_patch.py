import json
import shutil
from fixer import FixSelector
from patcher import patch_requirements, run_tests
from packaging.version import parse as parse_version
import tempfile
import os

def extract_candidates(finding):
    current_ver = parse_version(finding["current"])
    fixed_versions = {
        str(parse_version(f["version"]))
        for f in finding.get("fixes_available", [])
        if parse_version(f["version"]) > current_ver
    }
    return sorted(list(fixed_versions), key=parse_version)

def make_validator(temp_path):
    def validate(pkg, version):
        import tempfile
        import shutil
        import os

        patch = {pkg: version}
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmpfile:
            tmp_temp_path = tmpfile.name
        shutil.copy(temp_path, tmp_temp_path)

        patch_requirements(tmp_temp_path, patch)
        success = run_tests(tmp_temp_path)
        os.unlink(tmp_temp_path)
        return success

    return validate


def apply_fixes(
    fixes_path: str,
    requirements_path: str = "requirements.txt",
    temp_path: str = "temp_requirements.txt",
    recommended_requirements_path: str = "recommended_requirements.txt"
):
    # Copy initial requirements to temp file
    shutil.copy(requirements_path, temp_path)
    with open(fixes_path, "r") as f:
        findings = json.load(f)

    print("🔍 Validating current environment from base requirements.txt...")
    success, log = run_tests(temp_path)
    if not success:
        print("‼️ Error while validating requirements.")
        print("   Resolve conflicts in the current setup before applying fixes. Here is the exact error:")
        print(log)
        return

    fixer = FixSelector(validator=make_validator(temp_path))

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

        # Make a temp copy before patching
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmpfile:
            tmp_temp_path = tmpfile.name
        shutil.copy(temp_path, tmp_temp_path)

        patch_requirements(tmp_temp_path, single_patch)

        if run_tests(tmp_temp_path):
            print(f"✅ Patch succeeded for {result['package']}")
            shutil.copy(tmp_temp_path, temp_path)  # Commit the patch
        else:
            print(f"❌ Patch failed for {result['package']}. Skipping...")

        os.unlink(tmp_temp_path)

    shutil.copy(temp_path, recommended_requirements_path)
    print(f"\n📄 Final recommendations saved to {recommended_requirements_path}")
    os.remove(temp_path)
