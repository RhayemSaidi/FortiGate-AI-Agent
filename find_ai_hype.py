import re

keywords = [
    r"autonomous reasoning",
    r"self-learning",
    r"adaptive intelligence",
    r"autonomous cybersecurity decisions",
    r"fully autonomous remediation",
    r"intelligent decision-making",
    r"autonomous decision-making",
    r"autonomous execution",
    r"autonomous agent",
    r"intelligent agent",
    r"autonomous control",
    r"self-healing",
    r"cognitive plane",
    r"cognitive model",
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
            if re.search(kw, line, re.IGNORECASE):
                print(f"Line {idx+1} ({kw}): {line.strip()}")
