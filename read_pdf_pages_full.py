import pypdf

reader = pypdf.PdfReader(r"D:\PFE PROJECT\PFE_Report (1)\main.pdf")
for page_num in [4, 5, 6]: # Pages 5, 6, 7 (0-indexed: 4, 5, 6)
    print(f"================ PAGE {page_num + 1} ================")
    text = reader.pages[page_num].extract_text()
    print(text)
