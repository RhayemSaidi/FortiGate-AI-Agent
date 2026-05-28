import pypdf

reader = pypdf.PdfReader(r"D:\PFE PROJECT\PFE_Report (1)\main.pdf")
for page_num in [7, 8, 9]: # Pages 8, 9, 10 (0-indexed: 7, 8, 9)
    print(f"================ PAGE {page_num + 1} ================")
    text = reader.pages[page_num].extract_text()
    print(text)
