import pypdf

reader = pypdf.PdfReader(r"D:\PFE PROJECT\PFE_Report (1)\main.pdf")
print("--- PAGE 9 ---")
print(reader.pages[8].extract_text()[:600])
print("--- PAGE 10 ---")
print(reader.pages[9].extract_text()[:600])
