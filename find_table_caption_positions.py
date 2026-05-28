with open(r"D:\PFE PROJECT\PFE_Report (1)\chap1.tex", 'r', encoding='utf-8') as f:
    chap1_content = f.read()

with open(r"D:\PFE PROJECT\PFE_Report (1)\chap2.tex", 'r', encoding='utf-8') as f:
    chap2_content = f.read()

def find_all_tables(content, name):
    print(f"=== Tables in {name} ===")
    matches = re.finditer(r'\\begin\{table\}(.*?)\\end\{table\}', content, re.DOTALL)
    for m in matches:
        table_body = m.group(1)
        caption_match = re.search(r'\\caption\{(.*?)\}', table_body)
        caption = caption_match.group(1) if caption_match else "No caption"
        
        # Check if caption is before or after \begin{tabular}
        tabular_idx = table_body.find(r'\begin{tabular}')
        caption_idx = table_body.find(r'\caption')
        
        position = "BEFORE" if caption_idx < tabular_idx else "AFTER"
        print(f"Table Caption: '{caption}' | Position: {position}")

import re
find_all_tables(chap1_content, "chap1.tex")
find_all_tables(chap2_content, "chap2.tex")
