import re

def check_file(filepath):
    print(f"=== {filepath} ===")
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
    for idx, line in enumerate(lines):
        if 'caption' in line:
            print(f"Line {idx+1}: {line.strip()}")
            # print surrounding lines
            start = max(0, idx - 10)
            end = min(len(lines), idx + 5)
            for j in range(start, end):
                prefix = "-> " if j == idx else "   "
                print(f"{prefix}{j+1}: {lines[j].strip()}")
            print("-" * 50)

check_file(r"D:\PFE PROJECT\PFE_Report (1)\chap1.tex")
check_file(r"D:\PFE PROJECT\PFE_Report (1)\chap2.tex")
