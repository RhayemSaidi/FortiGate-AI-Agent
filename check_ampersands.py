import re

with open(r"D:\PFE PROJECT\PFE_Report (1)\chap3.tex", 'r', encoding='utf-8') as f:
    lines = f.readlines()

for idx, line in enumerate(lines):
    # Find all ampersands not preceded by a backslash
    matches = re.finditer(r'(?<!\\)&', line)
    for m in matches:
        print(f"Line {idx+1}: {line.strip()}")
