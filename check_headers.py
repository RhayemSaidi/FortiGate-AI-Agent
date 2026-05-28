import pypdf

reader = pypdf.PdfReader(r"D:\PFE PROJECT\PFE_Report (1)\main.pdf")
for page_num in range(4, 11): # Pages 5 to 11 (0-indexed: 4 to 10)
    print(f"================ PAGE {page_num + 1} ================")
    text = reader.pages[page_num].extract_text()
    lines = text.splitlines()
    print("First 3 lines:")
    for l in lines[:3]:
        print("  >", l)
    print("Last 2 lines:")
    for l in lines[-2:]:
        print("  >", l)
