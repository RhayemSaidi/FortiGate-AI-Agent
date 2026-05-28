import pypdf

reader = pypdf.PdfReader(r"D:\PFE PROJECT\PFE_Report (1)\main.pdf")
print("Total pages:", len(reader.pages))
for i in range(15):
    if i < len(reader.pages):
        text = reader.pages[i].extract_text()
        print(f"--- PAGE {i+1} ---")
        print(text[:200].replace('\n', ' | '))
