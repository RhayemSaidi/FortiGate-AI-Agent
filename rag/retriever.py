import os
import sys
import re
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rag.vectorstore import load_vectorstore

_vectorstore = None

# Query expansion map — short terms → richer search queries
QUERY_EXPANSIONS = {
    "vlan": "VLAN virtual LAN interface configuration vlanid FortiGate",
    "vpn": "VPN IPsec SSL tunnel configuration FortiGate",
    "nat": "NAT network address translation policy FortiGate",
    "ha": "high availability HA cluster FortiGate",
    "bgp": "BGP border gateway protocol routing FortiGate",
    "ospf": "OSPF routing protocol FortiGate",
    "ssl": "SSL VPN remote access FortiGate",
    "ipsec": "IPsec VPN tunnel phase1 phase2 FortiGate",
    "policy": "firewall policy rule traffic FortiGate",
    "route": "static route routing table FortiGate",
}


def get_vectorstore():
    global _vectorstore
    if _vectorstore is None:
        _vectorstore = load_vectorstore()
    return _vectorstore


def expand_query(query: str) -> str:
    """
    Expand short or vague queries into richer search terms.
    This fixes the mismatch between user terms and documentation language.
    """
    q_lower = query.lower().strip()

    # Check direct expansion map
    if q_lower in QUERY_EXPANSIONS:
        return QUERY_EXPANSIONS[q_lower]

    # Check if query contains a key term
    for term, expansion in QUERY_EXPANSIONS.items():
        if term in q_lower and len(q_lower) < 20:
            return expansion

    return query


def _is_useful_chunk(text: str) -> bool:
    """
    Filter out chunks that are pure parameter tables or page noise.
    CLI configuration examples are KEPT — they are useful for how-to questions.
    """
    if len(text.strip()) < 60:
        return False

    normalized = re.sub(r'\s+', ' ', text)

    # Pure parameter table indicators — these are never useful
    table_indicators = [
        "Minimum value:", "Maximum value:",
        "integer Minimum", "string Maximum length:",
        "Option Description", "POEreset",
    ]
    table_count = sum(
        1 for indicator in table_indicators
        if indicator.lower() in normalized.lower()
    )
    if table_count >= 2:
        return False

    # Garbled concatenated words
    words = normalized.split()
    long_words = [w for w in words if len(w) > 25 and not w.startswith('http')]
    if len(words) > 0 and len(long_words) > len(words) * 0.20:
        return False

    # NOTE: We no longer filter out CLI command chunks.
    # "config system interface / set vlanid / set type vlan" IS useful content
    # for how-to questions. Only filter if the chunk is ONLY commands
    # with zero explanatory text.
    lines = [l.strip() for l in text.split('\n') if l.strip()]
    if len(lines) >= 3:
        code_lines = sum(1 for l in lines if re.match(
            r'^(config|set|get|show|end|next|edit|unset)\s+\w+', l
        ))
        # Only filter if 90%+ of lines are raw CLI with no explanation
        if code_lines > len(lines) * 0.90:
            return False

    return True


def search(query: str, k: int = 4) -> str:
    """
    Search the knowledge base for the most relevant chunks.
    Applies query expansion and quality filtering.
    """
    vs = get_vectorstore()

    # Expand query before searching
    expanded = expand_query(query)

    # First check structured sources
    structured_results = []
    try:
        structured_results = vs.similarity_search(
            expanded, k=2,
            filter={"type": {"$in": ["error_code", "best_practice"]}}
        )
    except Exception:
        pass

    # Get more PDF results than needed so we can filter
    pdf_results = vs.similarity_search(expanded, k=k + 6)

    # Also try original query if expanded query gave few results
    if len(pdf_results) < 2 and expanded != query:
        pdf_results += vs.similarity_search(query, k=k + 4)

    # Merge: structured first then PDF, deduplicated
    seen = set()
    merged = []
    for doc in structured_results + pdf_results:
        key = doc.page_content[:100]
        if key not in seen:
            seen.add(key)
            merged.append(doc)

    # Apply quality filter
    merged = [doc for doc in merged if _is_useful_chunk(doc.page_content)]

    # Take top k
    merged = merged[:k]

    if not merged:
        return ""

    formatted = []
    for i, doc in enumerate(merged, 1):
        source = doc.metadata.get("source_file", "unknown")
        doc_type = doc.metadata.get("type", "")
        page = doc.metadata.get("page", "")

        if doc_type == "error_code":
            label = "FortiGate Error Codes Database"
        elif doc_type == "best_practice":
            label = "Security Best Practices"
        elif page:
            label = f"{source} — page {int(page) + 1}"
        else:
            label = source

        content = doc.page_content.strip()
        formatted.append(f"[Reference {i} — {label}]\n{content}")

    return "\n\n" + ("-" * 50 + "\n\n").join(formatted)


def search_errors(error_code: str) -> str:
    """Targeted search for FortiGate error codes."""
    vs = get_vectorstore()

    try:
        results = vs.similarity_search(
            f"FortiGate error code {error_code}",
            k=3,
            filter={"type": "error_code"}
        )
        if results:
            return "\n\n".join([doc.page_content.strip() for doc in results])
    except Exception:
        pass

    results = vs.similarity_search(f"FortiGate error {error_code}", k=3)
    if not results:
        return f"No documentation found for error code {error_code}."
    return "\n\n".join([doc.page_content.strip() for doc in results])