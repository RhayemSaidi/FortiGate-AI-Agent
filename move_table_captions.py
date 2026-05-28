import re

def process_file(filepath):
    print(f"Processing {filepath}...")
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Pattern to find table environments
    # We want to match \begin{table}[...] ... \end{table}
    # and swap the caption/label to the top.
    
    def replacer(match):
        table_block = match.group(0)
        
        # Find caption and label inside this block
        caption_match = re.search(r'\\caption\{([^}]+)\}', table_block)
        label_match = re.search(r'\\label\{([^}]+)\}', table_block)
        
        if not caption_match:
            return table_block # No caption, do nothing
            
        caption_str = caption_match.group(0)
        label_str = label_match.group(0) if label_match else ""
        
        # Remove caption and label from their current positions (with surrounding whitespace/newlines)
        # We replace them with empty string
        cleaned_block = table_block
        cleaned_block = cleaned_block.replace(caption_str, "")
        if label_str:
            cleaned_block = cleaned_block.replace(label_str, "")
            
        # Clean up any empty lines or double newlines at the bottom of the table
        # (where the caption and label used to be)
        # Find the end of tabular environment
        tabular_end = cleaned_block.rfind(r'\end{tabular}')
        if tabular_end != -1:
            end_index = tabular_end + len(r'\end{tabular}')
            table_close = cleaned_block.find(r'\end{table}', end_index)
            # Replace whitespace between \end{tabular} and \end{table}
            between = cleaned_block[end_index:table_close]
            cleaned_between = re.sub(r'\s*\n\s*', '\n    ', between)
            cleaned_block = cleaned_block[:end_index] + cleaned_between + cleaned_block[table_close:]
            
        # Now insert the caption and label at the top
        # We find \begin{table}[...] and \centering
        # We want to insert it right after \centering (if exists) or after \begin{table}[...]
        centering_match = re.search(r'\\centering', cleaned_block)
        if centering_match:
            insert_pos = centering_match.end()
            insert_text = f"\n    {caption_str}\n    {label_str}"
            new_block = cleaned_block[:insert_pos] + insert_text + cleaned_block[insert_pos:]
        else:
            begin_table = re.search(r'\\begin\{table\}(\[[^\]]+\])?', cleaned_block)
            insert_pos = begin_table.end()
            insert_text = f"\n    {caption_str}\n    {label_str}"
            new_block = cleaned_block[:insert_pos] + insert_text + cleaned_block[insert_pos:]
            
        return new_block

    new_content = re.sub(r'\\begin\{table\}(.*?)\\end\{table\}', process_table, content, flags=re.DOTALL)
    
    # Write back
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)

def process_table(match):
    table_block = match.group(0)
    
    caption_match = re.search(r'\\caption\{([^}]+)\}', table_block)
    label_match = re.search(r'\\label\{([^}]+)\}', table_block)
    
    if not caption_match:
        return table_block
        
    caption_str = caption_match.group(0)
    label_str = label_match.group(0) if label_match else ""
    
    # Remove from table block
    cleaned = table_block
    cleaned = cleaned.replace(caption_str, "")
    if label_str:
        cleaned = cleaned.replace(label_str, "")
        
    # Clean double newlines before \end{table}
    # Let's find where \end{tabular} is
    end_tab = cleaned.rfind(r'\end{tabular}')
    if end_tab != -1:
        end_idx = end_tab + len(r'\end{tabular}')
        end_tbl = cleaned.find(r'\end{table}', end_idx)
        cleaned = cleaned[:end_idx] + "\n" + cleaned[end_tbl:]
        
    # Insert caption & label at the top
    # Let's insert after \centering
    centering = re.search(r'\\centering\s*', cleaned)
    if centering:
        pos = centering.end()
        insertion = f"{caption_str}\n    {label_str}\n    "
        new_block = cleaned[:pos] + insertion + cleaned[pos:]
    else:
        begin_table = re.search(r'\\begin\{table\}(\[[^\]]+\])?\s*', cleaned)
        pos = begin_table.end()
        insertion = f"\n    {caption_str}\n    {label_str}"
        new_block = cleaned[:pos] + insertion + cleaned[pos:]
        
    return new_block

import sys
process_file(r"D:\PFE PROJECT\PFE_Report (1)\chap1.tex")
process_file(r"D:\PFE PROJECT\PFE_Report (1)\chap2.tex")
print("Successfully processed chap1.tex and chap2.tex")
