with open(r"D:\PFE PROJECT\PFE_Report (1)\main.log", 'r', encoding='utf-8', errors='ignore') as f:
    log_content = f.read()

lines = log_content.splitlines()

print("--- minitoc details in log ---")
in_minitoc = False
count = 0
for idx, line in enumerate(lines):
    if "minitoc" in line or "W00" in line:
        # print 5 lines before and after
        start = max(0, idx - 2)
        end = min(len(lines), idx + 8)
        print(f"\n--- Line {idx+1} ---")
        for i in range(start, end):
            print(f"{i+1}: {lines[i]}")
        count += 1
        if count > 20:
            break
