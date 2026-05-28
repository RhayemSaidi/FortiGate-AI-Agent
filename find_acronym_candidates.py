import re

files = [
    r"D:\PFE PROJECT\PFE_Report (1)\intro.tex",
    r"D:\PFE PROJECT\PFE_Report (1)\chap1.tex",
    r"D:\PFE PROJECT\PFE_Report (1)\chap2.tex",
]

acronyms = set()
for fpath in files:
    with open(fpath, 'r', encoding='utf-8') as f:
        content = f.read()
        
    # Find all capitalized words of length 3-6
    matches = re.findall(r'\b[A-Z]{3,6}\b', content)
    for m in matches:
        acronyms.add(m)

print("Found capitalized words of length 3-6:")
print(sorted(list(acronyms)))
