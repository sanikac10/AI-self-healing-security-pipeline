import os
import json
from openai import OpenAI
from typing import List, Dict, Any, Optional
import requests

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("OPENAI_API_KEY environment variable not set. Please export it: export OPENAI_API_KEY=your_key_here")

client = OpenAI(api_key=api_key)

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

class TreeNode:
    def __init__(self, search_query: str, parent=None):
        self.search_query = search_query
        self.parent = parent
        self.children = []
        self.results = []
        self.success_score = 0.0
        self.depth = parent.depth + 1 if parent else 0
        
    def add_child(self, child_node):
        child_node.parent = self
        child_node.depth = self.depth + 1
        self.children.append(child_node)

class AgenticSearchTree:
    def __init__(self, search_depth: int = 3, breadth_length: int = 3, max_nodes: int = 15):
        self.search_depth = search_depth
        self.breadth_length = breadth_length
        self.max_nodes = max_nodes
        self.total_nodes = 0
        self.root = None
        self.current_node = None
        self.search_policies = []
        
        self.decision_tools = [{
            "type": "function",
            "function": {
                "name": "search_decision",
                "description": "Analyze search results and decide next search direction",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "should_continue": {
                            "type": "string",
                            "enum": ["True", "False"]
                        },
                        "direction": {
                            "type": "string",
                            "enum": ["child", "sibling", "backtrack"]
                        },
                        "search_query": {
                            "type": "string"
                        },
                        "reasoning": {
                            "type": "string"
                        }
                    },
                    "required": ["should_continue", "direction", "search_query", "reasoning"]
                }
            },
            "strict": True
        }]
        
        self.policy_tools = [{
            "type": "function",
            "function": {
                "name": "generate_search_policy",
                "description": "Generate a search policy based on search experience",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "policy_name": {
                            "type": "string"
                        },
                        "code_patterns": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "search_strategies": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "successful_paths": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "avoid_patterns": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "policy_summary": {
                            "type": "string"
                        }
                    },
                    "required": ["policy_name", "code_patterns", "search_strategies", "successful_paths", "avoid_patterns", "policy_summary"]
                }
            },
            "strict": True
        }]

    def generate_initial_query(self, code_chunk: Dict[str, Any]) -> str:
        policy_context = ""
        if self.search_policies:
            relevant_policies = [p for p in self.search_policies 
                               if any(pattern in code_chunk['code'].lower() or 
                                     pattern in code_chunk.get('vulnerability_reason', '').lower()
                                     for pattern in p['code_patterns'])]
            
            if relevant_policies:
                policy_context = f"\nRELEVANT POLICIES:\n"
                for policy in relevant_policies[-2:]:
                    policy_context += f"- {policy['policy_name']}: {policy['policy_summary']}\n"

        prompt = f"""Generate an initial GitHub Security Advisory search query:

Language: {code_chunk['language']}
Function: {code_chunk['function_name']}
Vulnerability: {code_chunk.get('vulnerability_reason', 'Not specified')}
Code: {code_chunk['code'][:500]}...
{policy_context}

Create a concise search query targeting security vulnerabilities."""
        
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=100
        )
        
        return response.choices[0].message.content.strip()

    def analyze_and_decide(self, code_chunk: Dict[str, Any], current_results: List[Dict], search_history: List[str]) -> Dict[str, str]:
        context = f"""CODE CHUNK:
Language: {code_chunk['language']}
Function: {code_chunk['function_name']}
Vulnerability: {code_chunk.get('vulnerability_reason', 'Not specified')}
Code: {code_chunk['code'][:400]}...

CURRENT SEARCH RESULTS ({len(current_results)} found):
"""
        
        for i, result in enumerate(current_results[:3]):
            context += f"{i+1}. {result['summary']}\n   Severity: {result['severity']}\n\n"
        
        tree_info = ""
        if self.current_node:
            tree_info += f"\nCURRENT NODE: {self.current_node.search_query}\n"
            tree_info += f"DEPTH: {self.current_node.depth}/{self.search_depth}\n"
            
            if self.current_node.parent:
                tree_info += f"PARENT: {self.current_node.parent.search_query}\n"
                siblings = [child.search_query for child in self.current_node.parent.children if child != self.current_node]
                if siblings:
                    tree_info += f"EXISTING SIBLINGS: {siblings}\n"
        
        context += f"\nSEARCH HISTORY: {search_history}\n"
        context += tree_info
        context += f"NODES USED: {self.total_nodes}/{self.max_nodes}"
        
        system_prompt = """Analyze search results and decide next direction:

CHILD = Parent query + more specific terms (drill deeper)
SIBLING = Parent concept + different angle (avoid sibling terms) 
BACKTRACK = Go up tree, try different approach

should_continue "False" = Found enough or exhausted paths
should_continue "True" = Continue searching"""

        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": context}
            ],
            tools=self.decision_tools,
            tool_choice='required'
        )
        
        return json.loads(completion.choices[0].message.tool_calls[0].function.arguments)

    def generate_policy(self, code_chunk: Dict[str, Any], search_history: List[str], all_results: List[Dict]) -> Dict[str, Any]:
        context = f"""CODE CHUNK:
Language: {code_chunk['language']}
Function: {code_chunk['function_name']}
Vulnerability: {code_chunk.get('vulnerability_reason', 'Not specified')}
Code: {code_chunk['code'][:300]}...

SEARCH EXPERIENCE:
Queries: {search_history}
Results Found: {len(all_results)}

Generate a policy capturing what worked for this vulnerability type."""
        
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Generate search policies to improve future vulnerability searches."},
                {"role": "user", "content": context}
            ],
            tools=self.policy_tools,
            tool_choice='required'
        )
        
        return json.loads(completion.choices[0].message.tool_calls[0].function.arguments)

    def search_vulnerabilities(self, code_chunk: Dict[str, Any]) -> Dict[str, Any]:
        initial_query = self.generate_initial_query(code_chunk)
        self.root = TreeNode(initial_query)
        self.current_node = self.root
        self.total_nodes = 1
        
        search_history = []
        all_results = []
        
        while self.total_nodes < self.max_nodes:
            current_query = self.current_node.search_query
            search_history.append(current_query)
            
            search_results = search_github_advisories(current_query, limit=10)
            self.current_node.results = search_results
            all_results.extend(search_results)
            
            if search_results:
                self.current_node.success_score = len(search_results) / 10.0
            
            decision = self.analyze_and_decide(code_chunk, search_results, search_history)
            
            if decision['should_continue'] == "False":
                policy = self.generate_policy(code_chunk, search_history, all_results)
                self.search_policies.append(policy)
                
                return {
                    "status": "completed",
                    "total_results": len(all_results),
                    "search_history": search_history,
                    "final_results": all_results,
                    "generated_policy": policy
                }
            
            if decision['direction'] == "child":
                if self.current_node.depth >= self.search_depth:
                    decision['direction'] = "sibling"
                else:
                    new_child = TreeNode(decision['search_query'], self.current_node)
                    self.current_node.add_child(new_child)
                    self.current_node = new_child
                    self.total_nodes += 1
                    continue
            
            if decision['direction'] == "sibling":
                if self.current_node.parent and len(self.current_node.parent.children) < self.breadth_length:
                    new_sibling = TreeNode(decision['search_query'], self.current_node.parent)
                    self.current_node.parent.add_child(new_sibling)
                    self.current_node = new_sibling
                    self.total_nodes += 1
                    continue
                else:
                    decision['direction'] = "backtrack"
            
            if decision['direction'] == "backtrack":
                if self.current_node.parent and self.current_node.parent.parent:
                    self.current_node = self.current_node.parent.parent
                    continue
                else:
                    break
        
        policy = self.generate_policy(code_chunk, search_history, all_results)
        self.search_policies.append(policy)
        
        return {
            "status": "max_nodes_reached",
            "total_results": len(all_results),
            "search_history": search_history,
            "final_results": all_results,
            "generated_policy": policy
        }

    def print_tree(self, node=None, prefix="", is_last=True):
        if node is None:
            node = self.root
        
        if node is None:
            return
        
        connector = "└── " if is_last else "├── "
        print(f"{prefix}{connector}{node.search_query} ({len(node.results)} results)")
        
        extension = "    " if is_last else "│   "
        for i, child in enumerate(node.children):
            self.print_tree(child, prefix + extension, i == len(node.children) - 1)

def process_vulnerable_chunks(chunks_file: str = "vulnerable_chunks.json"):
    with open(chunks_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    vulnerable_chunks = data['vulnerable_chunks']
    results = []
    
    searcher = AgenticSearchTree(search_depth=3, breadth_length=3, max_nodes=15)
    
    for i, chunk in enumerate(vulnerable_chunks):
        print(f"\n{'='*80}")
        print(f"CHUNK {i+1}/{len(vulnerable_chunks)}: {chunk['function_name']}")
        print(f"File: {chunk['file_path']}")
        print(f"Language: {chunk['language']}")
        print(f"Vulnerability: {chunk.get('vulnerability_reason', 'Not specified')}")
        print(f"Policies learned so far: {len(searcher.search_policies)}")
        print(f"{'='*80}")
        
        search_result = searcher.search_vulnerabilities(chunk)
        
        print(f"\nSEARCH TREE:")
        searcher.print_tree()
        
        print(f"\nRESULTS:")
        print(f"Status: {search_result.get('status', 'unknown')}")
        print(f"Advisories found: {len(search_result.get('final_results', []))}")
        print(f"Search queries used: {len(search_result.get('search_history', []))}")
        
        if search_result.get('final_results'):
            print(f"\nSAMPLE ADVISORIES:")
            for j, advisory in enumerate(search_result['final_results'][:2]):
                print(f"  {j+1}. {advisory['summary']} (Severity: {advisory['severity']})")
        
        chunk_result = {
            "chunk_info": {
                "function_name": chunk['function_name'],
                "file_path": chunk['file_path'],
                "language": chunk['language'],
                "vulnerability_reason": chunk.get('vulnerability_reason', '')
            },
            "search_results": search_result
        }
        results.append(chunk_result)
    
    final_output = {
        "total_chunks_processed": len(vulnerable_chunks),
        "total_policies_learned": len(searcher.search_policies),
        "learned_policies": searcher.search_policies,
        "chunk_results": results
    }
    
    output_file = "advisory_search_results.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(final_output, f, indent=2, ensure_ascii=False)
    
    print(f"\n{'='*80}")
    print(f"FINAL SUMMARY")
    print(f"{'='*80}")
    print(f"Total chunks processed: {len(vulnerable_chunks)}")
    print(f"Total policies learned: {len(searcher.search_policies)}")
    
    total_advisories = sum(len(chunk['search_results'].get('final_results', [])) for chunk in results)
    print(f"Total advisories found: {total_advisories}")
    
    completed = sum(1 for chunk in results if chunk['search_results'].get('status') == 'completed')
    print(f"Searches completed: {completed}/{len(vulnerable_chunks)}")
    
    print(f"\nResults saved to: {output_file}")
    
    if searcher.search_policies:
        print(f"\nLEARNED POLICIES:")
        for i, policy in enumerate(searcher.search_policies):
            print(f"  {i+1}. {policy['policy_name']}")
            print(f"     Summary: {policy['policy_summary']}")
    
    return final_output

if __name__ == "__main__":
    chunks_file = input("Enter vulnerable chunks file (or press Enter for 'vulnerable_chunks.json'): ").strip()
    if not chunks_file:
        chunks_file = "vulnerable_chunks.json"
    
    try:
        result = process_vulnerable_chunks(chunks_file)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()