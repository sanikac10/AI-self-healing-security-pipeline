import json

def convert_dep_tree_to_dependency_tree(dep_tree):
    dependency_tree = {}
    package_map = {}
    for node in dep_tree['nodes']:
        package_name = node['package']
        version = node['version']
        if version != 'unknown':
            full_name = f"{package_name}=={version}"
        else:
            full_name = package_name
        package_map[package_name] = full_name
    for node in dep_tree['nodes']:
        package_name = node['package']
        full_name = package_map[package_name]
        dependency_tree[full_name] = []
    root_dependencies = []
    for node in dep_tree['nodes']:
        if node['is_direct']:
            package_name = node['package']
            full_name = package_map[package_name]
            root_dependencies.append(full_name)
    dependency_tree['my-web-app'] = root_dependencies
    for edge in dep_tree['edges']:
        from_package = edge['from'][0]
        from_version = edge['from'][1]
        to_package = edge['to'][0]
        to_version = edge['to'][1]
        if from_version != 'unknown':
            from_full = f"{from_package}=={from_version}"
        else:
            from_full = from_package
        if to_version != 'unknown':
            to_full = f"{to_package}=={to_version}"
        else:
            to_full = to_package
        if from_full in dependency_tree:
            if to_full not in dependency_tree[from_full]:
                dependency_tree[from_full].append(to_full)
        else:
            dependency_tree[from_full] = [to_full]
    return json.dumps(dependency_tree, indent=6)

import json

def convert_fixes_to_water_depths(fixes, dep_tree):
    water_depths = {}
    for node in dep_tree['nodes']:
        package_name = node['package']
        version = node['version']
        if version != 'unknown':
            full_name = f"{package_name}=={version}"
        else:
            full_name = package_name
        water_depths[full_name] = 0
    water_depths['my-web-app'] = 0
    for fix in fixes:
        package_name = fix['package']
        if fix['dependencyType'] == 'DIRECT':
            depth = 2
        else:
            depth = 1
        for node in dep_tree['nodes']:
            if node['package'] == package_name:
                version = node['version']
                if version != 'unknown':
                    full_name = f"{package_name}=={version}"
                else:
                    full_name = package_name
                water_depths[full_name] = depth
                break
    return json.dumps(water_depths, indent=6)

def convert_fixes_to_vulnerabilities(fixes, dep_tree):
    vulnerabilities = {}
    for fix in fixes:
        package_name = fix['package']
        for node in dep_tree['nodes']:
            if node['package'] == package_name:
                version = node['version']
                if version != 'unknown':
                    full_name = f"{package_name}=={version}"
                else:
                    full_name = package_name
                vulnerabilities[full_name] = [{
                    'number_of_versions_with_issue_fixed': len(fix['fixes_available']),
                    'dependencyType': fix['dependencyType']
                }]
                break
    return json.dumps(vulnerabilities, indent=6)

with open("fixes.json", "r") as f:
    fixes = json.load(f)

with open("dep_tree.json", "r") as f:
    dep_tree = json.load(f)

with open("visualization_template.html", "r") as f:
    html_template = "".join(f.readlines())
dependencyTree = convert_dep_tree_to_dependency_tree(dep_tree)
depths = convert_fixes_to_water_depths(fixes, dep_tree)
vulnerabilities = convert_fixes_to_vulnerabilities(fixes, dep_tree)
html_page = html_template.replace("$DEPENDENCY_TREE$", dependencyTree)
html_page = html_page.replace("$WATER_DEPTHS$", depths)
html_page = html_page.replace("$VULNERABILITIES$", vulnerabilities)
with open("index.html", "w") as f:
    f.write(html_page)