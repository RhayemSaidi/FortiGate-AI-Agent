# FortiGate AI Agent

This project is a conversational AI agent designed to manage FortiGate firewalls using natural language.  
It was developed as a final-year engineering project (PFE).

The goal is to simplify firewall administration by allowing administrators to use natural language (English or French) instead of the GUI or CLI. The agent translates requests into secure and validated FortiGate API actions.

---

# Features

## Read operations
- List firewall policies, address objects, interfaces, users, and static routes
- Retrieve system information (hostname, firmware version, model)
- Monitor CPU, memory, VPN status, and active sessions
- Perform full security analysis of the firewall configuration

## Write operations (require confirmation)
- Create, update, delete, enable, disable, and reorder firewall policies
- Create and delete address objects
- Modify interface management access (HTTP, HTTPS, SSH, Telnet)
- Block IP addresses for incident response
- Backup firewall configuration

## Knowledge base (RAG)
- Built from official Fortinet documentation
- Answers configuration and troubleshooting questions
- Supports English and French
- Uses semantic search with ChromaDB

---

# Architecture

The system is built using three main layers:

## 1. Natural Language Understanding (NLU)
- Mistral AI (mistral-small) interprets user input

## 2. Orchestration Layer
- Python-based intent detection and routing
- LangChain tools for structured execution
- Validation and confirmation pipeline

## 3. Execution Layer
- FortiGate REST API (v2)
- Communication via Python requests library

---

# Decision Flow

User Input
|
|-- Knowledge question
|     → RAG search (ChromaDB)
|     → LLM formats response
|
|-- Clear command
|     → Intent detection
|        |-- Read operation → Execute immediately
|        |-- Write operation → Validate → Confirm → Execute
|
|-- Ambiguous input
      → LLM fallback with tool access

---

# Safety System

All write operations follow a strict pipeline:

- Intent detection (deterministic, not LLM-based)
- Parameter extraction
- User confirmation
- Validation:
  - Parameter completeness
  - Format validation (IP, subnet, naming)
  - Existence checks
  - Conflict detection
  - Security analysis
- Warning handling (requires second confirmation if risky)
- Execution on FortiGate
- Verification of real state after execution
- Audit logging with SHA-256 integrity checks

---

# Project Structure

fortigate_agent/

├── config.py  
├── config.example.py  
├── main.py  
├── test_full.py  
├── app.py  
├── requirements.txt  

├── api/  
│   └── client.py  

├── modules/  
│   ├── system.py  
│   ├── monitor.py  
│   ├── policies.py  
│   ├── addresses.py  
│   ├── interfaces.py  
│   ├── routing.py  
│   ├── users.py  
│   ├── vpn.py  
│   ├── backup.py  
│   ├── logs.py  
│   └── services.py  

├── rag/  
│   ├── loader.py  
│   ├── vectorstore.py  
│   ├── retriever.py  
│   └── docs/  

├── audit/  
│   ├── logger.py  
│   └── report.py  

├── logs/  
│   └── audit.jsonl  

└── agent/  
    ├── agent.py  
    ├── tools.py  
    ├── prompt.py  
    ├── validator.py  
    └── insights.py  

---

# Setup

## Requirements
- Python 3.10+
- FortiGate with REST API enabled
- Mistral API key
- Ollama installed (for embeddings)

---

## Installation

pip install -r requirements.txt

---

## Install embedding model

ollama pull nomic-embed-text

---

## Configuration

Copy the example config:

config.example.py → config.py

Fill in:
- FortiGate IP address
- API token
- Mistral API key

---

# Knowledge Base Setup

Place Fortinet documentation PDFs inside:

rag/docs/

Then build the vector database:

python rag/vectorstore.py

---

# Running the Project

## CLI Agent

cd agent  
python agent.py  

## Web Interface

streamlit run app.py  

## Run Tests

python test_full.py  

---

# FortiGate API Token Setup

- Log in to FortiGate GUI  
- Go to System → Administrators  
- Create a REST API Admin  
- Assign permissions  
- Copy token into config.py  

---

# Example Commands

- list all firewall policies  
- check CPU and memory usage  
- analyze firewall security  
- create a policy named BlockHTTP from port1 to port2 denying HTTP  
- move policy 4 before policy 3  
- delete policy 4  
- disable policy BlockHTTP  
- enable policy BlockHTTP  
- create address named WebServer with subnet 192.168.10.50/32  
- delete address WebServer  
- block IP 192.168.1.99  
- disable HTTP and TELNET on port2  
- backup the configuration  
- what does error -651 mean?  
- how do I configure a VLAN on FortiGate?  

---

# Known Limitations

The test environment runs on a FortiGate VM with a trial license:

- Maximum of 3 firewall policies  
- Some API operations may be restricted  
- Backup functionality may be limited  

These are environment limitations, not implementation issues.

---

# Future Improvements

- Role-based access control (RBAC)  
- Automated task scheduling  
- Improved UI  
- Docker deployment  
- Architecture diagram  

---

# Technology Stack

- LLM: Mistral AI (mistral-small)  
- Embeddings: nomic-embed-text (Ollama)  
- Vector DB: ChromaDB  
- Orchestration: LangChain  
- Backend: Python  
- UI: Streamlit  
- Logging: JSONL + SHA-256  

---

# Security Considerations

- config.py excluded from version control  
- All write operations require confirmation  
- Protection against accidental lockouts  
- Full audit logging with tamper detection  
- No credentials stored in memory  
