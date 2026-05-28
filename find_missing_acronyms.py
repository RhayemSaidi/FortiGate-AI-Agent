import re

# Read defined acronyms from acronymes.tex
defined_acronyms = set()
with open(r"D:\PFE PROJECT\PFE_Report (1)\acronymes.tex", 'r', encoding='utf-8') as f:
    for line in f:
        match = re.search(r'\\acro\{([^}]+)\}', line)
        if match:
            defined_acronyms.add(match.group(1))

print("Defined acronyms:", sorted(list(defined_acronyms)))

# Files to scan
files_to_scan = [
    r"D:\PFE PROJECT\PFE_Report (1)\intro.tex",
    r"D:\PFE PROJECT\PFE_Report (1)\chap1.tex",
    r"D:\PFE PROJECT\PFE_Report (1)\chap2.tex",
    r"D:\PFE PROJECT\PFE_Report (1)\chap3.tex",
    r"D:\PFE PROJECT\PFE_Report (1)\chap4.tex",
]

# Find acronyms in files (words with 2+ uppercase letters)
used_acronyms = set()
for filepath in files_to_scan:
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            # Strip out LaTeX commands except their contents if they are text
            # Find words like CLI, API, LLM, etc.
            # Avoid matching LaTeX command names (which start with backslash)
            words = re.findall(r'\b[A-Z]{2,}\b', content)
            for w in words:
                # Exclude common LaTeX structural/command elements if they happen to match
                # e.g., PNG, REST (REST API), etc.
                if w not in {"AND", "OR", "THE", "IN", "TO", "A", "OF", "FOR", "BY", "ON", "WITH", "HTML", "CSS"}:
                    used_acronyms.add(w)
    except FileNotFoundError:
        pass

print("\nUsed acronyms in text:", sorted(list(used_acronyms)))

missing = used_acronyms - defined_acronyms
print("\nMissing acronyms:", sorted(list(missing)))
