import pypdf

reader = pypdf.PdfReader(r"D:\PFE PROJECT\GuidePFEISI  (2).pdf")
print("Total pages:", len(reader.pages))

# Let's extract the table of contents or first few pages to understand the structure
print("--- PAGE 1 ---")
print(reader.pages[0].extract_text()[:1000])

print("--- PAGE 2 ---")
print(reader.pages[1].extract_text()[:1000])

print("--- PAGE 3 ---")
print(reader.pages[2].extract_text()[:1000])

print("--- PAGE 4 ---")
print(reader.pages[3].extract_text()[:1000])

# Let's also search for terms like "structure", "chapitre", "rapport", "pagination"
text_all = ""
for idx, page in enumerate(reader.pages):
    text_all += f"\n--- Page {idx+1} ---\n" + page.extract_text()

# Write the text to a temporary file in artifacts so we can read it easily
with open(r"C:\Users\ideap\.gemini\antigravity\brain\33c9c7e3-c937-485b-93f1-026720982660\artifacts\isi_pfe_guide_text.txt", "w", encoding="utf-8") as f:
    f.write(text_all)

print("Saved guide text to artifacts/isi_pfe_guide_text.txt")
