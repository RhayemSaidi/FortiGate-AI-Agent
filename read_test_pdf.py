import pypdf

reader = pypdf.PdfReader(r"D:\PFE PROJECT\PFE_Report (1)\test_toc.pdf")
print("Total pages:", len(reader.pages))
print("--- PAGE 1 ---")
print(reader.pages[0].extract_text())
print("--- PAGE 2 ---")
print(reader.pages[1].extract_text())
