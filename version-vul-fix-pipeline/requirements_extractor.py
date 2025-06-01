#!/usr/bin/env python3
import sys
import json
import subprocess
import re
from typing import Set, List, Tuple

def parse_requirements(requirements_path: str) -> List[str]:
    packages = []
    try:
        with open(requirements_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    package_name = re.split(r'[>=<!]', line)[0].strip()
                    if package_name:
                        packages.append(package_name)
    except FileNotFoundError:
        print(f"Error: Could not find {requirements_path}")
        sys.exit(1)
    return packages

def get_package_info(package_name: str) -> Tuple[str, List[str]]:
    try:
        result = subprocess.run(['pip', 'show', package_name], capture_output=True, text=True, check=True)
        version = ""
        deps = []
        for line in result.stdout.split('\n'):
            if line.startswith('Version:'):
                version = line.replace('Version:', '').strip()
            elif line.startswith('Requires:'):
                deps_str = line.replace('Requires:', '').strip()
                if deps_str and deps_str != 'None':
                    deps = [dep.strip() for dep in deps_str.split(',') if dep.strip()]
        return f"{package_name}=={version}", deps
    except subprocess.CalledProcessError:
        print(f"Warning: Could not get info for package '{package_name}'")
        return f"{package_name}==unknown", []

def build_dependency_tree(root_packages: List[str]) -> Tuple[Set[str], List[Tuple[str, str]]]:
    nodes = set()
    edges = []
    visited = set()
    package_versions = {}
    def process_package(package_name: str):
        if package_name in visited:
            return
        visited.add(package_name)
        versioned_name, dependencies = get_package_info(package_name)
        package_versions[package_name] = versioned_name
        nodes.add(versioned_name)
        for dep in dependencies:
            if dep not in package_versions:
                process_package(dep)
            dep_versioned = package_versions.get(dep, f"{dep}==unknown")
            nodes.add(dep_versioned)
            edges.append((versioned_name, dep_versioned))
    for package in root_packages:
        process_package(package)
    return nodes, edges

def main(requirements_path):
    root_packages = parse_requirements(requirements_path)
    if not root_packages:
        print("No packages found in requirements.txt")
        sys.exit(1)
    nodes, edges = build_dependency_tree(root_packages)
    result = {"nodes": list(nodes), "edges": edges}
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main("/Users/sanikachavan/Desktop/AI-self-healing-security-pipeline/AI-self-healing-security-pipeline/version-vul-fix-pipeline/requirements.txt")