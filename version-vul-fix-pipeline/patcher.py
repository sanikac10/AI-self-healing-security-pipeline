import re
import subprocess

def patch_requirements(requirements_path: str, fixes: dict[str, str]):
    with open(requirements_path, "r") as f:
        lines = f.readlines()

    new_lines = []
    for line in lines:
        original = line.strip()
        for pkg, new_ver in fixes.items():
            pattern = re.compile(rf"^{re.escape(pkg)}([=><!~]=)?([\w.\-]+)?", re.IGNORECASE)
            match = pattern.match(original)
            if match:
                old_ver = match.group(2)
                if old_ver and old_ver != new_ver:
                    print(f"Updating {pkg}: {old_ver} → {new_ver}")
                return_line = f"{pkg}=={new_ver}\n"
                line = return_line
                break
        new_lines.append(line)

    with open(requirements_path, "w") as f:
        f.writelines(new_lines)


def run_tests(requirements_path="requirements.txt") -> (bool, str):
    try:
        print("🔧 Installing dependencies...")
        install_proc = subprocess.run(
            ["pip", "install", "-r", requirements_path],
            check=True,
            capture_output=True,
            text=True
        )

        print("🧪 Running tests...")
        test_proc = subprocess.run(
            ["pytest"],
            check=True,
            capture_output=True,
            text=True
        )

        return True, install_proc.stdout + test_proc.stdout

    except subprocess.CalledProcessError as e:
        return False, e.stderr


