# FortiGate AI Agent

AI-powered conversational system for managing FortiGate firewalls using natural language.

This project was developed as a final-year engineering project (PFE). It enables administrators to interact with firewall infrastructure using English or French instead of CLI or GUI, while ensuring secure, validated, and auditable execution of all operations.

---

# Overview

FortiGate AI Agent acts as an intelligent abstraction layer over FortiGate REST APIs. It interprets user requests, understands intent using a language model, retrieves contextual knowledge when needed, and executes safe, validated firewall operations.

The system is designed with security, traceability, and enterprise-grade validation as core principles.

---

# Key Features

## Natural Language Firewall Management
- Control FortiGate using English or French commands
- Support for both direct commands and conversational queries
- Intelligent intent detection and routing

## Read Operations (safe, no confirmation required)
- Firewall policies, address objects, interfaces, users
- System information (CPU, memory, firmware, hostname)
- Active sessions and VPN status
- Security and configuration analysis

## Write Operations (secured pipeline)
All modification actions require confirmation and validation:
- Create, update, delete firewall policies
- Manage address objects and services
- Modify interface access settings (HTTP, HTTPS, SSH, Telnet)
- Block malicious IP addresses
- Backup firewall configuration

## Knowledge Base (RAG System)
- Built from official Fortinet documentation
- Semantic search using ChromaDB
- Context-aware responses for troubleshooting and configuration
- Bilingual support (English / French)

## Security and Audit System
- Full audit logging of all operations
- SHA-256 tamper-evident log integrity
- Multi-stage validation pipeline
- Protection against unsafe configuration changes

---

# System Architecture

The system is structured into three main layers:

## 1. Natural Language Layer
- Mistral AI (mistral-small)
- Interprets user input and extracts intent

## 2. Orchestration Layer
- Python-based control logic
- Intent detection and routing
- LangChain tool execution
- Validation and confirmation system

## 3. Execution Layer
- FortiGate REST API (v2)
- Secure HTTP communication via requests library
- Real-time firewall configuration updates

---

# Architecture Flow

User Request  
→ Natural Language Understanding (LLM)  
→ Intent Detection  

If Knowledge Query:
→ RAG Search (ChromaDB)
→ Contextual Response Generation

If Command:
→ Read Operation → Execute directly  
→ Write Operation → Validate → Confirm → Execute → Verify  

If Ambiguous:
→ LLM Tool-Based Reasoning

---

# Project Structure

The project is organized in a modular architecture separating the AI agent, API layer, firewall modules, RAG system, audit system, and core application entry points.

```text
FortiGate-AI-Agent/
│
├── app.py
├── main.py
├── test_full.py
├── requirements.txt
├── README.md
├── .gitignore
├── config.example.py
├── config.py
│
├── agent/
│   ├── agent.py
│   ├── tools.py
│   ├── prompt.py
│   ├── validator.py
│   ├── insights.py
│   └── __init__.py
│
├── api/
│   ├── client.py
│   └── __init__.py
│
├── audit/
│   ├── logger.py
│   ├── report.py
│   └── __init__.py
│
├── logs/
│   └── audit.jsonl
│
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
│   ├── services.py
│   └── __init__.py
│
├── rag/
│   ├── loader.py
│   ├── retriever.py
│   ├── vectorstore.py
│   ├── add_best_practices.py
│   ├── docs/
│   └── __init__.py
│
└── docs/

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
