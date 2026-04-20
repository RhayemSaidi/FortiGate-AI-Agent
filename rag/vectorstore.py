import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma
from rag.loader import load_all_documents

# Where ChromaDB stores its data on disk
CHROMA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chroma_db")


def get_embeddings():
    """Use Ollama's local embedding model — no API key needed."""
    return OllamaEmbeddings(model="nomic-embed-text")


def build_vectorstore():
    """
    Load all documents, embed them, and save to ChromaDB.
    This only needs to run ONCE — after that load_vectorstore() is used.
    WARNING: The Admin Guide is huge — this will take 10-30 minutes.
    """
    print("=" * 60)
    print("  Building RAG Vector Store")
    print("  This runs once and saves to disk.")
    print("=" * 60)

    print("\n[1/3] Loading documents...")
    documents = load_all_documents()

    if not documents:
        print(" No documents found. Check your rag/docs/ folder.")
        return None

    print(f"\n[2/3] Embedding {len(documents)} chunks with nomic-embed-text...")
    print("      This will take a while for the large Admin Guide. Please wait...\n")

    embeddings = get_embeddings()

    # Build and persist the vector store
    vectorstore = Chroma.from_documents(
        documents=documents,
        embedding=embeddings,
        persist_directory=CHROMA_DIR
    )

    print(f"\n[3/3] Vector store saved to {CHROMA_DIR}")
    print(f" Done! {len(documents)} chunks indexed and ready for search.")
    return vectorstore


def load_vectorstore():
    """
    Load an existing ChromaDB vector store from disk.
    Call this after build_vectorstore() has been run once.
    """
    if not os.path.exists(CHROMA_DIR):
        raise FileNotFoundError(
            "Vector store not found. Run build_vectorstore() first."
        )
    embeddings = get_embeddings()
    return Chroma(
        persist_directory=CHROMA_DIR,
        embedding_function=embeddings
    )


if __name__ == "__main__":
    build_vectorstore()



def add_documents_to_vectorstore(documents):
    """
    Add new documents to an existing vector store without rebuilding.
    Use this to add a single file after the initial build.
    """
    if not os.path.exists(CHROMA_DIR):
        print("❌ Vector store not found. Run build_vectorstore() first.")
        return

    print(f"Adding {len(documents)} new chunks to existing vector store...")
    embeddings = get_embeddings()
    vs = Chroma(
        persist_directory=CHROMA_DIR,
        embedding_function=embeddings
    )
    vs.add_documents(documents)
    print(f"✅ Done! {len(documents)} chunks added.")