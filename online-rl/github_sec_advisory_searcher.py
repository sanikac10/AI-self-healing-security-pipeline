import requests
import os

def search_github_advisories(issue_string, token=None, limit=5, ecosystem=None, severity=None):
    if not token:
        token = os.getenv("GITHUB_TOKEN")
    
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    query = """
    {
        securityAdvisories(first: 100, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
            nodes {
                ghsaId
                summary
                description
                severity
                publishedAt
                identifiers { type value }
            }
        }
    }
    """
    
    response = requests.post("https://api.github.com/graphql", 
                           json={"query": query}, headers=headers)
    
    if response.status_code != 200:
        return []
    
    data = response.json()
    nodes = data.get("data", {}).get("securityAdvisories", {}).get("nodes", [])
    
    results = []
    for node in nodes:
        if severity and node["severity"].upper() != severity.upper():
            continue
        if ecosystem and ecosystem.lower() not in node["description"].lower():
            continue
            
        text = f"{node['summary']} {node['description']}".lower()
        if any(word.lower() in text for word in issue_string.split()):
            cve = next((i["value"] for i in node["identifiers"] if i["type"] == "CVE"), None)
            results.append({
                "ghsa_id": node["ghsaId"],
                "summary": node["summary"],
                "description": node["description"],
                "severity": node["severity"],
                "cve_id": cve,
                "published_at": node["publishedAt"]
            })
    
    return results[:limit]

if __name__=='__main__':
    r = search_github_advisories("vulnerable oauth token in js")
    print(r)