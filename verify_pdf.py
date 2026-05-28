import pypdf
import os

pdf_path = r"D:\PFE PROJECT\PFE_Report (1)\main.pdf"

if not os.path.exists(pdf_path):
    print("PDF NOT FOUND!")
    exit(1)

reader = pypdf.PdfReader(pdf_path)
print("Total pages:", len(reader.pages))
for i in range(len(reader.pages)):
    text = reader.pages[i].extract_text()
    if "Conception" in text or "System Architecture" in text:
        print(f"Page {i+1} mentions Conception/Architecture")
