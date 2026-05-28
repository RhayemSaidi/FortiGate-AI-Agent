import pypdf
import copy
import sys

sys.stdout.reconfigure(encoding='utf-8')

reader = pypdf.PdfReader(r"D:\PFE PROJECT\PFE_Report (1)\main.pdf")
print("Page | Header Text")
print("-" * 50)
for idx, original_page in enumerate(reader.pages):
    page_num = idx + 1
    
    # Create a copy so we don't mutate the original reader state
    page = copy.copy(original_page)
    
    # Get page dimensions
    bbox = page.mediabox
    width = float(bbox.width)
    height = float(bbox.height)
    
    # Crop to the header area (top 55pt)
    page.mediabox.top = height - 15
    page.mediabox.bottom = height - 60
    page.mediabox.left = 0
    page.mediabox.right = width
    
    header_text = page.extract_text().strip().replace('\n', ' | ')
    
    if header_text:
        # Keep only the first 100 characters to make it readable
        snippet = header_text[:120]
        print(f"{page_num:4d} | {snippet}")
