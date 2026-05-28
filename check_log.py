with open(r"D:\PFE PROJECT\PFE_Report (1)\main.log", 'r', encoding='utf-8', errors='ignore') as f:
    log_content = f.read()

lines = log_content.splitlines()

print("--- TOC/LOF/LOT related lines in log ---")
for i, line in enumerate(lines, 1):
    lower_line = line.lower()
    if ".toc" in lower_line or ".lof" in lower_line or ".lot" in lower_line or "contents" in lower_line:
        print(f"Line {i}: {line}")

print("\n--- Warnings in log ---")
for i, line in enumerate(lines, 1):
    if "Warning" in line or "Error" in line:
        print(f"Line {i}: {line}")
