import os
import json
from typing import List
from langchain_community.document_loaders import PyPDFLoader
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

# Path to the docs folder
DOCS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs")


import re

def _clean_text(text: str) -> str:
    """
    Clean raw PDF text extraction artifacts more aggressively.
    """
    # Remove Fortinet page headers and footers
    text = re.sub(r'FortiOS[\s\d\.]+(?:Administration Guide|CLI Reference|Log Reference|Best Practices)[^\n]*', '', text)
    text = re.sub(r'Fortinet\s*Inc\.?', '', text)
    text = re.sub(r'www\.fortinet\.com[^\n]*', '', text)

    # Fix CamelCase concatenation from bad PDF extraction
    # e.g. "configsystemglobal" → "config system global"
    text = re.sub(r'([a-z])([A-Z][a-z])', r'\1 \2', text)
    text = re.sub(r'([a-zA-Z])(\d)', r'\1 \2', text)
    text = re.sub(r'(\d)([a-zA-Z])', r'\1 \2', text)

    # Remove lines that are purely parameter table rows
    lines = text.split('\n')
    clean_lines = []
    for line in lines:
        # Skip pure table lines
        if re.match(r'^\s*(integer|string|option|enable|disable)\s+\w+', line):
            continue
        if re.match(r'^\s*Minimum\s+value:', line):
            continue
        if re.match(r'^\s*Maximum\s+value:', line):
            continue
        clean_lines.append(line)
    text = '\n'.join(clean_lines)

    # Clean up whitespace
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = re.sub(r' {2,}', ' ', text)
    text = text.strip()

    return text


def load_pdf(filepath: str, chunk_size: int = 1000, chunk_overlap: int = 150) -> list:
    """
    Load a PDF and split it into clean overlapping chunks.
    """
    print(f"  Loading PDF: {os.path.basename(filepath)}")
    loader = PyPDFLoader(filepath)
    pages = loader.load()

    # Clean each page before splitting
    for page in pages:
        page.page_content = _clean_text(page.page_content)

    # Remove pages that are essentially empty after cleaning
    pages = [p for p in pages if len(p.page_content.strip()) > 50]

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        separators=["\n\n", "\n", ".", " "]
    )

    chunks = splitter.split_documents(pages)

    # Add source metadata to every chunk
    for chunk in chunks:
        chunk.metadata["source_file"] = os.path.basename(filepath)
        chunk.metadata["type"] = "pdf"

    print(f"    → {len(pages)} pages → {len(chunks)} chunks")
    return chunks

def load_json_errors(filepath: str) -> List[Document]:
    """
    Load the FortiGate error codes JSON file.
    Each error code becomes its own document for precise retrieval.
    """
    print(f"  Loading JSON: {os.path.basename(filepath)}")
    with open(filepath, "r", encoding="utf-8") as f:
        errors = json.load(f)

    documents = []
    for error in errors:
        # Build a rich text representation of each error
        content = (
            f"FortiGate Error Code: {error.get('code', 'unknown')}\n"
            f"Meaning: {error.get('meaning', '')}\n"
            f"Cause: {error.get('cause', '')}\n"
            f"Fix: {error.get('fix', '')}"
        )
        doc = Document(
            page_content=content,
            metadata={
                "source_file": os.path.basename(filepath),
                "type": "error_code",
                "error_code": str(error.get("code", ""))
            }
        )
        documents.append(doc)

    print(f"    → {len(documents)} error code entries loaded")
    return documents


def load_json_best_practices(filepath: str) -> List[Document]:
    """
    Load the security best practices JSON file.
    """
    print(f"  Loading JSON: {os.path.basename(filepath)}")
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    documents = []

    # Handle both list format and dict format
    if isinstance(data, list):
        for item in data:
            content = (
                f"Category: {item.get('category', '')}\n"
                f"Practice: {item.get('practice', '')}\n"
                f"Reason: {item.get('reason', '')}\n"
                f"Implementation: {item.get('implementation', '')}"
            )
            doc = Document(
                page_content=content,
                metadata={
                    "source_file": os.path.basename(filepath),
                    "type": "best_practice",
                    "category": item.get("category", "")
                }
            )
            documents.append(doc)
    elif isinstance(data, dict):
        for category, practices in data.items():
            if isinstance(practices, list):
                for practice in practices:
                    content = f"Category: {category}\nPractice: {practice}"
                    doc = Document(
                        page_content=content,
                        metadata={
                            "source_file": os.path.basename(filepath),
                            "type": "best_practice",
                            "category": category
                        }
                    )
                    documents.append(doc)

    print(f"    → {len(documents)} best practice entries loaded")
    return documents


def load_all_documents() -> List[Document]:
    """
    Load every document in the docs folder.
    Applies different strategies per file type.
    Uses smaller chunks for the huge Admin Guide to save memory.
    """
    all_docs = []

    # Define chunk sizes per file — smaller for huge files
    pdf_configs = {
        "FortiOS-7.6.6-Administration_Guide.pdf": {"chunk_size": 800, "chunk_overlap": 100},
        "FortiOS-7.6.6-CLI_Reference.pdf":        {"chunk_size": 600, "chunk_overlap": 100},
        "FortiOS_7.6.6_Log_Reference.pdf":         {"chunk_size": 700, "chunk_overlap": 100},
        "FortiOS-7.6.0-Best_Practices.pdf":        {"chunk_size": 1000, "chunk_overlap": 150},
        "FortiOS-7.6-Troubleshooting_Cheat_Sheet.pdf": {"chunk_size": 500, "chunk_overlap": 80},
    }

    json_files = {
        "fortigate_errors.json": "errors",
        "securtiy_best_practices.json": "best_practices",
    }

    files_in_docs = os.listdir(DOCS_DIR)

    for filename in files_in_docs:
        filepath = os.path.join(DOCS_DIR, filename)

        if filename.endswith(".pdf"):
            config = pdf_configs.get(filename, {"chunk_size": 800, "chunk_overlap": 100})
            try:
                chunks = load_pdf(filepath, **config)
                all_docs.extend(chunks)
            except Exception as e:
                print(f"  Failed to load {filename}: {e}")

        elif filename in json_files:
            try:
                file_type = json_files[filename]
                if file_type == "errors":
                    docs = load_json_errors(filepath)
                else:
                    docs = load_json_best_practices(filepath)
                all_docs.extend(docs)
            except Exception as e:
                print(f"  Failed to load {filename}: {e}")

    print(f"\n Total chunks loaded: {len(all_docs)}")
    return all_docs