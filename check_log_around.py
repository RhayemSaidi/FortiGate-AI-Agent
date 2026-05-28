with open(r"D:\PFE PROJECT\PFE_Report (1)\main.log", 'r', encoding='utf-8', errors='ignore') as f:
    lines = f.readlines()

for idx in range(1270, 1340):
    if idx < len(lines):
        print(f"Line {idx+1}: {lines[idx]}", end='')
