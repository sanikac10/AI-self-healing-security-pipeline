import os
import openai
from dotenv import load_dotenv
from typing import List, Dict
from packaging.version import parse as parse_version
import json

load_dotenv()

def sort_candidates(current_version: str, candidates: List[Dict]) -> List[Dict]:
    current = parse_version(current_version)
    return sorted(
        candidates,
        key=lambda c: abs(parse_version(c["version"]) - current)
    )

FIX_FUNCTION_SCHEMA = {
    "name": "choose_fix",
    "description": "Select the best version upgrade for a vulnerable package based on severity, semver distance, and safety.",
    "parameters": {
        "type": "object",
        "properties": {
            "package": {"type": "string", "description": "Name of the package to upgrade."},
            "chosen_version": {"type": "string", "description": "Selected safe upgrade version."},
            "rationale": {"type": "string", "description": "Justification for the chosen version."}
        },
        "required": ["package", "chosen_version", "rationale"],
        "additionalProperties": False
    }
}

class FixSelector:
    def __init__(self, model_name="gpt-4o", api_key=None, base_url=None):
        self.model_name = model_name
        self.client = openai.OpenAI(
            api_key=os.getenv("OPENAI_API_KEY")
        )

    def _sort_candidates(self, current_version, candidates):
        def version_to_tuple(v):
            parsed = parse_version(v)
            return tuple(int(part) for part in str(parsed).split('.') if part.isdigit())

        current_tuple = version_to_tuple(current_version)

        def distance(candidate_version):
            cand_tuple = version_to_tuple(candidate_version)
            length = max(len(current_tuple), len(cand_tuple))
            cur = current_tuple + (0,) * (length - len(current_tuple))
            cand = cand_tuple + (0,) * (length - len(cand_tuple))
            return sum(abs(a - b) * (10 ** (length - i - 1)) for i, (a, b) in enumerate(zip(cur, cand)))

        return sorted(candidates, key=lambda c: distance(c["version"]))


    def _auto_choose_fix(self, pkg, current, candidates):
        sorted_candidates = self._sort_candidates(current, candidates)
        print(sorted_candidates)
        top = sorted_candidates[0]
        return {
            "package": pkg,
            "chosen_version": top["version"],
            "rationale": f"Closest safe version to current ({current})."
        }

    def choose_fix(self, package_info: Dict, use_llm=True) -> Dict:
        if not use_llm:
            return self._auto_choose_fix(
                pkg=package_info["package"],
                current=package_info["current"],
                candidates=package_info["candidates"]
            )

        prompt = (
            f"Package `{package_info['package']}` (current: {package_info['current']}) has vulnerabilities.\n"
            "Choose the closest safe upgrade version unless there's a strong reason to go higher.\n"
            "Candidates:\n"
        )
        for c in self._sort_candidates(package_info["current"], package_info["candidates"]):
            prompt += f"- {c['version']} (CVSS: {c.get('cvss', 'N/A')})\n"

        prompt += "\nRespond with your decision and rationale."

        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=[{"role": "user", "content": prompt}],
            tools=[{"type": "function", "function": FIX_FUNCTION_SCHEMA}],
            tool_choice="required"
        )

        return json.loads(response.choices[0].message.tool_calls[0].function.arguments)

