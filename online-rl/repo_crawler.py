import os
import json
import re
from typing import List, Dict, Any, Set
from pathlib import Path
import mimetypes

class UniversalRepoCrawler:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.chunks = []
        
        self.patterns = {
            'python': {
                'function': r'^\s*def\s+(\w+)\s*\(',
                'class': r'^\s*class\s+(\w+)\s*[:\(]',
                'extensions': ['.py']
            },
            'javascript': {
                'function': r'^\s*(?:function\s+(\w+)|const\s+(\w+)\s*=\s*(?:\([^)]*\)\s*=>|function)|(\w+)\s*:\s*(?:async\s+)?function)',
                'class': r'^\s*class\s+(\w+)',
                'extensions': ['.js', '.jsx', '.ts', '.tsx', '.mjs']
            },
            'java': {
                'function': r'^\s*(?:public|private|protected|static|\s)*\s*\w+\s+(\w+)\s*\(',
                'class': r'^\s*(?:public|private|protected)?\s*class\s+(\w+)',
                'extensions': ['.java']
            },
            'cpp': {
                'function': r'^\s*(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*{',
                'class': r'^\s*class\s+(\w+)',
                'extensions': ['.cpp', '.cc', '.cxx', '.c', '.h', '.hpp']
            },
            'csharp': {
                'function': r'^\s*(?:public|private|protected|internal|static|\s)*\s*\w+\s+(\w+)\s*\(',
                'class': r'^\s*(?:public|private|protected|internal)?\s*class\s+(\w+)',
                'extensions': ['.cs']
            },
            'go': {
                'function': r'^\s*func\s+(?:\([^)]*\)\s+)?(\w+)\s*\(',
                'class': r'^\s*type\s+(\w+)\s+struct',
                'extensions': ['.go']
            },
            'rust': {
                'function': r'^\s*(?:pub\s+)?fn\s+(\w+)\s*\(',
                'class': r'^\s*(?:pub\s+)?struct\s+(\w+)',
                'extensions': ['.rs']
            },
            'php': {
                'function': r'^\s*(?:public|private|protected)?\s*function\s+(\w+)\s*\(',
                'class': r'^\s*class\s+(\w+)',
                'extensions': ['.php']
            },
            'ruby': {
                'function': r'^\s*def\s+(\w+)',
                'class': r'^\s*class\s+(\w+)',
                'extensions': ['.rb']
            },
            'swift': {
                'function': r'^\s*(?:public|private|internal)?\s*func\s+(\w+)\s*\(',
                'class': r'^\s*(?:public|private|internal)?\s*class\s+(\w+)',
                'extensions': ['.swift']
            },
            'kotlin': {
                'function': r'^\s*(?:public|private|internal|protected)?\s*fun\s+(\w+)\s*\(',
                'class': r'^\s*(?:public|private|internal|protected)?\s*class\s+(\w+)',
                'extensions': ['.kt', '.kts']
            },
            'scala': {
                'function': r'^\s*def\s+(\w+)\s*[:\(]',
                'class': r'^\s*class\s+(\w+)',
                'extensions': ['.scala']
            }
        }
        
        self.ignore_extensions = {
            '.pyc', '.pyo', '.class', '.o', '.obj', '.exe', '.dll', '.so',
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
            '.pdf', '.doc', '.docx', '.zip', '.tar', '.gz',
            '.mp3', '.mp4', '.avi', '.mov', '.wav'
        }
        
        self.skip_dirs = {
            '.git', '.svn', '.hg', '__pycache__', 'node_modules', 
            '.vscode', '.idea', 'build', 'dist', 'target', 'bin', 'obj'
        }

    def detect_language(self, file_path: Path) -> str:
        ext = file_path.suffix.lower()
        for lang, config in self.patterns.items():
            if ext in config['extensions']:
                return lang
        return 'unknown'

    def extract_functions_and_classes(self, file_path: Path, content: str, language: str) -> List[Dict[str, Any]]:
        chunks = []
        
        if language == 'unknown':
            return self.chunk_unknown_language(file_path, content)
        
        patterns = self.patterns[language]
        lines = content.split('\n')
        
        func_pattern = re.compile(patterns['function'], re.MULTILINE)
        for i, line in enumerate(lines):
            func_match = func_pattern.match(line)
            if func_match:
                func_name = next((g for g in func_match.groups() if g), 'unknown')
                
                start_line = i + 1
                end_line = self.find_block_end(lines, i, language)
                func_code = '\n'.join(lines[i:end_line])
                
                chunk = {
                    'chunk_type': 'function',
                    'language': language,
                    'function_name': func_name,
                    'file_path': str(file_path.relative_to(self.repo_path)),
                    'start_line': start_line,
                    'end_line': end_line,
                    'code': func_code,
                    'file_size': len(content)
                }
                chunks.append(chunk)
        
        if 'class' in patterns:
            class_pattern = re.compile(patterns['class'], re.MULTILINE)
            for i, line in enumerate(lines):
                class_match = class_pattern.match(line)
                if class_match:
                    class_name = next((g for g in class_match.groups() if g), 'unknown')
                    
                    start_line = i + 1
                    end_line = self.find_block_end(lines, i, language)
                    class_code = '\n'.join(lines[i:end_line])
                    
                    chunk = {
                        'chunk_type': 'class',
                        'language': language,
                        'class_name': class_name,
                        'function_name': class_name,
                        'file_path': str(file_path.relative_to(self.repo_path)),
                        'start_line': start_line,
                        'end_line': end_line,
                        'code': class_code,
                        'file_size': len(content)
                    }
                    chunks.append(chunk)
        
        return chunks

    def find_block_end(self, lines: List[str], start_idx: int, language: str) -> int:
        if language in ['python']:
            base_indent = len(lines[start_idx]) - len(lines[start_idx].lstrip())
            for i in range(start_idx + 1, len(lines)):
                line = lines[i]
                if line.strip() == '':
                    continue
                current_indent = len(line) - len(line.lstrip())
                if current_indent <= base_indent and line.strip():
                    return i
            return len(lines)
        
        else:
            brace_count = 0
            found_opening = False
            for i in range(start_idx, len(lines)):
                line = lines[i]
                for char in line:
                    if char == '{':
                        brace_count += 1
                        found_opening = True
                    elif char == '}':
                        brace_count -= 1
                        if found_opening and brace_count == 0:
                            return i + 1
            
            for i in range(start_idx + 1, min(start_idx + 50, len(lines))):
                if any(pattern in lines[i] for pattern in ['function', 'def', 'class', 'func']):
                    return i
            
            return min(start_idx + 30, len(lines))

    def chunk_unknown_language(self, file_path: Path, content: str) -> List[Dict[str, Any]]:
        lines = content.split('\n')
        chunks = []
        
        potential_patterns = [
            r'^\s*\w+\s*\([^)]*\)\s*{',
            r'^\s*function\s+\w+',
            r'^\s*def\s+\w+',
            r'^\s*\w+:\s*function',
            r'^\s*public\s+\w+',
            r'^\s*private\s+\w+',
        ]
        
        for i, line in enumerate(lines):
            for pattern in potential_patterns:
                if re.match(pattern, line):
                    chunk_end = min(i + 25, len(lines))
                    chunk_code = '\n'.join(lines[i:chunk_end])
                    
                    chunk = {
                        'chunk_type': 'code_block',
                        'language': 'unknown',
                        'function_name': f"block_{i+1}",
                        'file_path': str(file_path.relative_to(self.repo_path)),
                        'start_line': i + 1,
                        'end_line': chunk_end,
                        'code': chunk_code,
                        'file_size': len(content)
                    }
                    chunks.append(chunk)
                    break
        
        if not chunks and len(content) > 100:
            chunk = {
                'chunk_type': 'file',
                'language': 'unknown',
                'function_name': file_path.stem,
                'file_path': str(file_path.relative_to(self.repo_path)),
                'start_line': 1,
                'end_line': len(lines),
                'code': content[:2000],
                'file_size': len(content)
            }
            chunks.append(chunk)
        
        return chunks

    def is_text_file(self, file_path: Path) -> bool:
        if file_path.suffix.lower() in self.ignore_extensions:
            return False
        
        mime_type, _ = mimetypes.guess_type(str(file_path))
        if mime_type and mime_type.startswith('text'):
            return True
        
        for lang_config in self.patterns.values():
            if file_path.suffix.lower() in lang_config['extensions']:
                return True
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                sample = f.read(1024)
                printable_ratio = sum(1 for c in sample if c.isprintable() or c.isspace()) / len(sample) if sample else 0
                return printable_ratio > 0.7
        except:
            return False

    def crawl_directory(self, directory: Path = None) -> None:
        if directory is None:
            directory = self.repo_path
            
        try:
            for item in directory.iterdir():
                if item.is_file() and self.is_text_file(item):
                    try:
                        content = None
                        for encoding in ['utf-8', 'utf-8-sig', 'latin1', 'cp1252']:
                            try:
                                with open(item, 'r', encoding=encoding) as f:
                                    content = f.read()
                                break
                            except UnicodeDecodeError:
                                continue
                        
                        if content is None:
                            continue
                        
                        language = self.detect_language(item)
                        chunks = self.extract_functions_and_classes(item, content, language)
                        self.chunks.extend(chunks)
                        
                    except Exception as e:
                        pass
                
                elif item.is_dir() and item.name not in self.skip_dirs:
                    self.crawl_directory(item)
                    
        except PermissionError:
            pass
        except Exception as e:
            pass

    def get_chunks(self) -> List[Dict[str, Any]]:
        return self.chunks

    def save_chunks_to_json(self, output_file: str = "universal_code_chunks.json"):
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.chunks, f, indent=2, ensure_ascii=False)

    def print_summary(self):
        total_chunks = len(self.chunks)
        languages = {}
        chunk_types = {}
        for chunk in self.chunks:
            lang = chunk['language']
            chunk_type = chunk['chunk_type']
            languages[lang] = languages.get(lang, 0) + 1
            chunk_types[chunk_type] = chunk_types.get(chunk_type, 0) + 1
        print(f"=== UNIVERSAL CRAWL SUMMARY ===")
        print(f"Total chunks: {total_chunks}")
        print(f"Files processed: {len(set(c['file_path'] for c in self.chunks))}")
        print(f"\nLanguages detected:")
        for lang, count in sorted(languages.items(), key=lambda x: x[1], reverse=True):
            print(f"  {lang}: {count} chunks")
        print(f"\nChunk types:")
        for chunk_type, count in sorted(chunk_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  {chunk_type}: {count}")

if __name__ == "__main__":
    repo_path = "/Users/ampriyan/Downloads/PigeonAssistez-main"#input("Enter repository path (any language): ").strip()
    
    if not os.path.exists(repo_path):
        print(f"Path {repo_path} does not exist!")
        exit(1)
    
    crawler = UniversalRepoCrawler(repo_path)
    crawler.crawl_directory()
    crawler.print_summary()
    crawler.save_chunks_to_json()
    
    chunks = crawler.get_chunks()
    if chunks:
        print(f"\n=== SAMPLE CHUNKS ===")
        shown_langs = set()
        for chunk in chunks[:5]:
            lang = chunk['language']
            if lang not in shown_langs:
                print(f"\n[{lang.upper()}] {chunk['chunk_type']}: {chunk['function_name']}")
                print(f"File: {chunk['file_path']}")
                print(f"Code preview: {chunk['code'][:150]}...")
                shown_langs.add(lang)