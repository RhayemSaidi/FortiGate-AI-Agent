import re

def check_latex_formatting():
    filepath = r"D:\PFE PROJECT\PFE_Report (1)\chap2.tex"
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        
    lines = content.splitlines()
    
    # 1. Check double spaces (excluding leading spaces for indentation)
    for i, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if "  " in stripped:
            print(f"Line {i}: Double space detected: '{line}'")
            
    # 2. Check double punctuation
    for i, line in enumerate(lines, 1):
        if re.search(r'\.\.', line):
            print(f"Line {i}: Double period detected: '{line}'")
        if re.search(r',,', line):
            print(f"Line {i}: Double comma detected: '{line}'")
            
    # 3. Check spacing before \cite and \ref (should use non-breaking space ~)
    for i, line in enumerate(lines, 1):
        if " \\cite" in line:
            print(f"Line {i}: Normal space before \\cite: '{line}'")
        if " \\ref" in line:
            print(f"Line {i}: Normal space before \\ref: '{line}'")
            
    # 4. Check e.g., and i.e., spacing (should be e.g.,\ or similar)
    for i, line in enumerate(lines, 1):
        if re.search(r'e\.g\.,\s', line) and not re.search(r'e\.g\.,\\', line):
            print(f"Line {i}: Space after e.g., should be escaped: '{line}'")
        if re.search(r'i\.e\.,\s', line) and not re.search(r'i\.e\.,\\', line):
            print(f"Line {i}: Space after i.e., should be escaped: '{line}'")

if __name__ == "__main__":
    check_latex_formatting()
