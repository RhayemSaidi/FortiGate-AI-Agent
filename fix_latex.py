import re

def fix_latex_formatting():
    filepath = r"D:\PFE PROJECT\PFE_Report (1)\chap2.tex"
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        
    # Replace normal space before \cite with non-breaking space ~
    content = content.replace(" \\cite", "~\\cite")
    
    # Replace normal space before \ref with non-breaking space ~
    content = content.replace(" \\ref", "~\\ref")
    
    # Replace double spaces with a single space
    # (except for indentation spaces at the start of a line)
    # We can split by line, replace multiple spaces in stripped lines, and reassemble
    lines = content.splitlines()
    fixed_lines = []
    for line in lines:
        stripped = line.lstrip()
        indent = line[:len(line) - len(stripped)]
        # Replace multiple spaces with a single space in the non-indent part
        fixed_stripped = re.sub(r' {2,}', ' ', stripped)
        fixed_lines.append(indent + fixed_stripped)
        
    content = "\n".join(fixed_lines)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
        
    print("Formatting fixes completed successfully!")

if __name__ == "__main__":
    fix_latex_formatting()
