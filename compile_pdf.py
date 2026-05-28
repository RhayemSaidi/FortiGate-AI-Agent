import subprocess
import os

def compile_pdf():
    pdflatex = r"D:\PFE PROJECT\texlive\2026\bin\windows\pdflatex.exe"
    bibtex = r"D:\PFE PROJECT\texlive\2026\bin\windows\bibtex.exe"
    workdir = r"D:\PFE PROJECT\PFE_Report (1)"
    
    print("Running pdflatex (first pass)...")
    p1 = subprocess.run([pdflatex, "-interaction=nonstopmode", "main.tex"], cwd=workdir, capture_output=True, text=True)
    print(f"pdflatex exit code: {p1.returncode}")
    
    print("Running bibtex...")
    b = subprocess.run([bibtex, "main"], cwd=workdir, capture_output=True, text=True)
    print(f"bibtex exit code: {b.returncode}")
    print("Bibtex stdout:", b.stdout)
    print("Bibtex stderr:", b.stderr)
    
    print("Running pdflatex (second pass)...")
    p2 = subprocess.run([pdflatex, "-interaction=nonstopmode", "main.tex"], cwd=workdir, capture_output=True, text=True)
    print(f"pdflatex exit code: {p2.returncode}")
    
    print("Running pdflatex (third pass)...")
    p3 = subprocess.run([pdflatex, "-interaction=nonstopmode", "main.tex"], cwd=workdir, capture_output=True, text=True)
    print(f"pdflatex exit code: {p3.returncode}")
    print("Compilation completed!")

if __name__ == "__main__":
    compile_pdf()
