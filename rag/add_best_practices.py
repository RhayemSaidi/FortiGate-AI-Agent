import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rag.loader import load_json_best_practices
from rag.vectorstore import add_documents_to_vectorstore

filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs", "securtiy_best_practices.json")
docs = load_json_best_practices(filepath)
add_documents_to_vectorstore(docs)