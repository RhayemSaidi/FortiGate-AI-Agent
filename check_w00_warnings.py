with open(r"D:\PFE PROJECT\PFE_Report (1)\main.log", 'r', encoding='utf-8', errors='ignore') as f:
    lines = f.readlines()

for idx, line in enumerate(lines):
    if "W00" in line:
        print(f"Line {idx+1}:")
        # print from idx to idx + 5
        for i in range(idx, min(len(lines), idx + 10)):
            print(f"  {lines[i].strip()}")
