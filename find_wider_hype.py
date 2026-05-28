import re

keywords = [
    r"autonomous",
    r"intelligent",
    r"agent",
    r"decision",
    r"reasoning",
    r"self-learning",
    r"adaptive",
]

files = [
    r"D:\PFE PROJECT\PFE_Report (1)\intro.tex",
    r"D:\PFE PROJECT\PFE_Report (1)\chap1.tex",
    r"D:\PFE PROJECT\PFE_Report (1)\chap2.tex",
]

for fp in files:
    print(f"\nScanning {fp}...")
    with open(fp, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    for idx, line in enumerate(lines):
        for kw in keywords:
            matches = list(re.finditer(kw, line, re.IGNORECASE))
            if matches:
                print(f"Line {idx+1} ({kw}): {line.strip()}")
                break # Only print once per line
