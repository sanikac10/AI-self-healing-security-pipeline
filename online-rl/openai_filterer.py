import json
from openai import OpenAI
from typing import List, Dict, Any
from tqdm import tqdm
import os

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("OPENAI_API_KEY environment variable not set. Please export it: export OPENAI_API_KEY=your_key_here")

client = OpenAI(api_key=api_key)

tools = [{
    "type": "function",
    "function": {
        "name": "vulnerability_filter",
        "description": "Analyze code chunks and determine if each contains potential security vulnerabilities. Return exactly one boolean (true/false) for each code chunk provided, indicating whether the chunk contains vulnerable code patterns.",
        "parameters": {
            "type": "object",
            "properties": {
                "vulnerability_results": {
                    "type": "array",
                    "description": "Array of vulnerability assessments for each code chunk in order",
                    "items": {
                        "type": "object",
                        "properties": {
                            "is_vulnerable": {
                                "type": "string",
                                "enum": ["True", "False"]
                            },
                            "reason": {
                                "type": "string"
                            }
                        },
                        "required": ["is_vulnerable", "reason"]
                    }
                }
            },
            "required": ["vulnerability_results"]
        }
    },
    "strict": True
}]

SYSTEM_PROMPT = """You are a security expert analyzing code chunks for potential vulnerabilities. For each code chunk provided, determine if it contains security vulnerabilities or insecure coding patterns.

VULNERABILITY DETECTION CRITERIA:
- SQL injection vulnerabilities (unsanitized database queries)
- Cross-site scripting (XSS) vulnerabilities (unsanitized user input in output)
- Authentication and authorization flaws
- Input validation failures
- Insecure cryptographic implementations
- Buffer overflows and memory safety issues
- Path traversal vulnerabilities
- Insecure deserialization
- Command injection vulnerabilities
- Hardcoded secrets or credentials
- Insecure random number generation
- Race conditions and concurrency issues
- Improper error handling that leaks sensitive information

ANALYSIS INSTRUCTIONS:
- Analyze each code chunk independently
- Look for actual vulnerability patterns, not just theoretical risks
- Consider the context and implementation details
- Return true if the code chunk contains potential vulnerabilities
- Return false if the code appears secure or contains only safe patterns
- Focus on exploitable vulnerabilities rather than code quality issues

OUTPUT FORMAT:
- Return exactly one assessment object for each code chunk provided
- Each object should have "is_vulnerable" (True/False) and "reason" (brief explanation)
- Maintain the same order as the input chunks
- Keep reasons concise but specific to the vulnerability found or why it's safe"""

def filter_vulnerable_chunks(chunks_file: str = "universal_code_chunks.json") -> tuple[List[bool], List[str]]:
    with open(chunks_file, 'r', encoding='utf-8') as f:
        chunks = json.load(f)
    
    results = []
    reasons = []
    batch_size = 5
    
    for i in tqdm(range(0, len(chunks), batch_size), desc="Analyzing chunks"):
        batch = chunks[i:i + batch_size]
        
        batch_text = ""
        for idx, chunk in enumerate(batch):
            batch_text += f"CHUNK {idx + 1}:\n"
            batch_text += f"Language: {chunk['language']}\n"
            batch_text += f"Function: {chunk['function_name']}\n"
            batch_text += f"Code:\n{chunk['code']}\n\n"
        
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": batch_text}
            ],
            tools=tools,
            tool_choice='required'
        )
        
        output = json.loads(completion.choices[0].message.tool_calls[0].function.arguments)
        batch_results = [result['is_vulnerable'] == "True" for result in output['vulnerability_results']]
        batch_reasons = [result['reason'] for result in output['vulnerability_results']]
        results.extend(batch_results)
        reasons.extend(batch_reasons)
    
    return results, reasons

def save_filtered_chunks(chunks_file: str = "universal_code_chunks.json", output_file: str = "vulnerable_chunks.json") -> Dict[str, Any]:
    with open(chunks_file, 'r', encoding='utf-8') as f:
        all_chunks = json.load(f)
    
    vulnerability_flags, vulnerability_reasons = filter_vulnerable_chunks(chunks_file)
    
    vulnerable_chunks = []
    
    for chunk, is_vulnerable, reason in zip(all_chunks, vulnerability_flags, vulnerability_reasons):
        chunk['is_vulnerable'] = is_vulnerable
        chunk['vulnerability_reason'] = reason
        if is_vulnerable:
            vulnerable_chunks.append(chunk)
    
    filtered_data = {
        'total_chunks': len(all_chunks),
        'vulnerable_count': len(vulnerable_chunks),
        'safe_count': len(all_chunks) - len(vulnerable_chunks),
        'vulnerable_chunks': vulnerable_chunks
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(filtered_data, f, indent=2, ensure_ascii=False)
    
    return filtered_data

if __name__ == "__main__":
    chunks_file = "universal_code_chunks.json"
    
    print("Filtering vulnerable chunks...")
    result = save_filtered_chunks(chunks_file)
    
    print(f"=== VULNERABILITY FILTER RESULTS ===")
    print(f"Total chunks analyzed: {result['total_chunks']}")
    print(f"Vulnerable chunks: {result['vulnerable_count']}")
    print(f"Safe chunks: {result['safe_count']}")
    print(f"Vulnerability rate: {result['vulnerable_count']/result['total_chunks']*100:.1f}%")
    print(f"Results saved to: vulnerable_chunks.json")