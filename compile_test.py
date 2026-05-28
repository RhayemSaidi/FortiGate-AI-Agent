import subprocess
import os

pdflatex = r"D:\PFE PROJECT\texlive\2026\bin\windows\pdflatex.exe"
workdir = r"D:\PFE PROJECT\PFE_Report (1)"

# Run pdflatex twice
for i in range(2):
    print(f"--- Run {i+1} ---")
    res = subprocess.run([pdflatex, "-interaction=nonstopmode", "test_toc.tex"], cwd=workdir, capture_output=True, text=True)
    print("STDOUT:", res.stdout[-300:])
    print("STDERR:", res.stderr)
    print("Exit code:", res.returncode)
