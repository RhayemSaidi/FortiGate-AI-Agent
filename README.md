<div align="center">
  <h1>FortiGate AI Agent</h1>
  <p><strong>Deterministic AI Orchestration for FortiOS Network Control Planes</strong></p>
  
  [![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
  [![FortiOS](https://img.shields.io/badge/FortiOS-REST_API-E31837?style=for-the-badge&logo=fortinet&logoColor=white)](https://fortinet.com)
  [![Mistral](https://img.shields.io/badge/Mistral_AI-NLU_Engine-F24E1E?style=for-the-badge)](https://mistral.ai)
  [![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](#license)
</div>

<br/>

## 1. Project Description

<div align="center">
  <!-- Place your Streamlit dashboard screenshot here -->
  <img src="docs/images/dashboard_preview.png" alt="FortiGate AI Agent Dashboard" width="800"/>
</div>
<br/>

**FortiGate AI Agent** is an enterprise-grade orchestration platform that allows network administrators to manage, query, and audit FortiGate firewalls using natural language. 

Unlike standard "chatbot" implementations that grant LLMs dangerous autonomous execution capabilities, this project introduces a **Hybrid Deterministic Architecture**. Large Language Models (LLMs) are strictly confined to Natural Language Understanding (NLU) and intent parsing. All downstream operations—including state validation, compliance enforcement, execution guarantees, snapshotting, and rollback—are handled entirely by verifiable, deterministic Python logic.

This ensures zero risk of LLM hallucination leading to infrastructure misconfiguration.

---

## 2. Key Features

- **Natural Language Control Plane**: Manage complex routing, firewall policies, custom services, and interface configurations in conversational English or French.
- **Zero-Trust AI Architecture**: LLMs extract intent; Python code executes. The LLM cannot write configuration.
- **Snapshot & Rollback Engine**: Pre-state capture for all modifying operations allowing instant, deterministic rollbacks.
- **Active Compliance Enforcement**: Prevents dangerous configurations (e.g., implicit `ALL to ALL` rules, unencrypted management protocols) before they hit the firewall.
- **RAG-Powered Knowledge Base**: Instant answers to FortiOS troubleshooting and architecture questions using a localized vector database containing official documentation.
- **Cryptographic Audit Trail**: All operations log to a tamper-evident, SHA-256 hashed audit file.
- **Containerized Deployment**: Ready for immediate production rollout via Docker Compose.

---

## 3. Core Architecture Philosophy

The core philosophy of this project is **Safety through Determinism**. 

In infrastructure-as-code and automated network management, the cost of a hallucination is catastrophic network outage or security compromise. To leverage the UX benefits of AI without the operational risks, we draw a strict trust boundary:
1. **The LLM is a translator.** It parses human language into structured JSON payloads (`RawIntentSchema`).
2. **The LLM is not trusted.** The structured JSON is cross-referenced against live firewall state (Grounding), validated against security best practices (Compliance), and verified post-execution (Verification).

---

## 4. Deterministic Trust Boundary Explanation

The "Trust Boundary" is the point in the request lifecycle where AI involvement ends and deterministic code takes over.

In this agent, the boundary sits immediately after the `NLU Interpreter`. Once a `RawIntentSchema` is generated, the LLM is suspended. The agent takes the schema and enters a closed loop of API calls, state checks, and deterministic validation. If the LLM hallucinates an IP address, the Grounding Engine catches it. If the LLM attempts to allow HTTP, the Compliance Engine blocks it. The LLM never writes API requests and never verifies its own success.

---

## 5. System Architecture Overview

```text
┌─────────────────┐      ┌─────────────────────┐      ┌─────────────────────────┐
│                 │      │                     │      │                         │
│   User Input    ├─────►│  Intent Router      ├─────►│  Knowledge Base (RAG)   │
│                 │      │  (Regex & Semantic) │      │  (ChromaDB + Ollama)    │
└─────────────────┘      └──────────┬──────────┘      └─────────────────────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
   [TRUST BOUNDARY]      │  NLU Interpreter    │
   ......................│  (Mistral LLM)      │.................................
                         └──────────┬──────────┘
                                    │ JSON Intent Payload
                                    ▼
                         ┌─────────────────────┐
                         │  Grounding Engine   │◄────── [ Live API State ]
                         │  (Name Resolution)  │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Validation Pipeline │
                         │ & Compliance Engine │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Pre-Write Snapshot  │
                         │ (Rollback Store)    │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐      ┌─────────────────────────┐
                         │  Action Executor &  ├─────►│    FortiGate FireOS     │
                         │  State Verifier     │◄─────┤    REST API Endpoint    │
                         └─────────────────────┘      └─────────────────────────┘
```

---

## 6. Request Lifecycle Flow

1. **Routing**: The user's query is classified as either `LIVE_READ`, `WRITE_ACTION`, `KNOWLEDGE`, or `CONVERSATIONAL`.
2. **NLU Extraction**: For write actions, the query is parsed into an `UpdateIntent` or `CreateIntent` schema.
3. **Grounding**: The `nlu_grounder.py` translates named entities (e.g., "my web server") into API-ready IDs by polling the FortiGate.
4. **Validation**: The `validator.py` ensures the grounded intent doesn't violate core rules.
5. **Human Confirmation**: The execution pauses. A unified diff of the proposed changes is presented to the user.
6. **Snapshot**: Pre-state is pulled and saved to memory.
7. **Execution**: The REST API call is dispatched.
8. **Verification**: The agent re-queries the FortiGate, comparing the new state against the requested intent, returning absolute proof of success.

---

## 7. Tech Stack

- **Orchestration**: Python 3.10+, LangChain
- **AI / NLU**: Mistral AI (mistral-small)
- **Embeddings & RAG**: Ollama (`nomic-embed-text`), ChromaDB
- **User Interface**: Streamlit
- **Network Backend**: FortiOS REST API v2
- **Data Serialization**: Pydantic, Dataclasses

---

## 8. Repository Structure

```text
FortiGate-AI-Agent/
├── agent/                  # Core deterministic orchestration logic
│   ├── core.py             # AgentSession state machine
│   ├── nlu_interpreter.py  # Mistral system prompt & schema definitions
│   ├── nlu_grounder.py     # Live state reconciliation
│   ├── validator.py        # Security & logic validation
│   ├── compliance.py       # Enterprise posture enforcement
│   ├── snapshot.py         # Rollback engine
│   └── verifier.py         # Post-execution verification
├── api/                    # Core REST request wrappers
├── audit/                  # Cryptographic logging engine
├── modules/                # FortiGate endpoint abstractions (Policies, Routes, Users)
├── rag/                    # Vector database & document loaders
├── tests/                  # Pytest validation suite
├── ui/                     # Modular Streamlit components & styling
└── streamlit_app.py        # Web application entry point
```

---

## 9. Safety & Security Model

This system implements **Fail-Safe Defaults**. 
* If the LLM generates a malformed schema, execution aborts. 
* If a policy ID does not exist, execution aborts. 
* If an API call drops packets, execution aborts. 

API tokens are never exposed to the LLM and are loaded exclusively via environment configurations. All operational payloads are constructed natively in Python.

---

## 10. Validation & Compliance Engine

The `compliance.py` engine enforces strict operational paradigms overriding user intent if deemed unsafe. 
* **Implicit Deny Protection**: Prevents creating policies with `action=accept` and `srcintf=any` + `dstintf=any`.
* **Insecure Management**: Blocks attempts to enable `Telnet` or `HTTP` on interfaces, forcing encrypted alternatives.
* **Port Safety**: Identifies high-risk port exposure (e.g., exposing SMB/3389 to WAN interfaces).

---

## 11. Snapshot & Rollback System

Before any state-mutating API call (`tool_update_policy`, `tool_move_policy`, etc.), `snapshot.py` interrupts execution. It fetches the exact structural JSON of the target resource or its sequence position.

If an administrator issues the `rollback` command, the deterministic rollback engine triggers the mapped inversion function (e.g., pushing the old JSON via `PUT`, or issuing a reverse sequence `move`), guaranteeing safe recovery from erroneous instructions.

---

## 12. Verification Engine

The LLM is blind to network state post-execution. The `verifier.py` module explicitly polls the FortiOS REST API after an HTTP 200 OK is received from a write action. It compares the returned properties against the generated `UpdateIntent` to ensure the delta was applied correctly, preventing phantom success states.

---

## 13. Conversational Clarification System

If the `nlu_grounder.py` detects a missing mandatory parameter (e.g., the user says *"Move policy 4"* but omits the destination), it raises a `GroundingIssue`. The state machine pauses, preserves the intent in the session context, and asks the user: *"Please specify which policy to move relative to."* Upon reply, the parameters are merged, and execution resumes.

---

## 14. Routing Architecture

Semantic routing is expensive and prone to latency. `router.py` employs a Stage-1 Regex matching engine for high-frequency queries (`show policies`, `rollback history`). If regex fails, Stage-2 LLM classification bins the query into strict operational categories, ensuring read-only queries never touch the write pipeline.

---

## 15. NLU & Grounding Pipeline

The NLU interpreter forces Mistral to respond strictly in JSON. The Grounding pipeline then executes a reconciliation algorithm:
* Normalizes strings.
* Validates IP address subnets using Python's `ipaddress` library.
* Maps human-readable object names to FortiOS internal UUIDs/Seq-nums.

---

## 16. Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/RhayemSaidi/FortiGate-AI-Agent.git
   cd FortiGate-AI-Agent
   ```
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Install Ollama and embedding model:**
   ```bash
   # Ensure Ollama is running on your host
   ollama pull nomic-embed-text
   ```

---

## 17. Environment Configuration

Copy the example configuration file:
```bash
cp config.example.py config.py
```
Edit `config.py` with your credentials:
```python
FORTIGATE_IP = "192.168.1.99"
API_TOKEN    = "your_fortios_api_token"
MISTRAL_KEY  = "your_mistral_api_key"
VERIFY_SSL   = False  # Set to True for production
```

---

## 18. Running the Project

**To launch the Web Interface (Streamlit):**
```bash
streamlit run streamlit_app.py
```

**To use the lightweight CLI interface:**
```bash
python agent/agent.py
```

---

## 19. Example Commands

* **Read**: `"Show me all firewall policies."`
* **Create**: `"Create a route to 10.0.0.0/24 via 192.168.1.1 on port1."`
* **Update**: `"Add SSH and HTTPS to policy 4, and enable NAT."`
* **Reorder**: `"Move policy 4 before policy 3."`
* **Remediate**: `"Block IP 192.168.50.2 immediately."`
* **Recover**: `"Rollback the last action."`

---

## 20. Example Agent Interactions

**User:** Move policy 4 before 3.  
**Agent:** 
```text
=======================================================
  CONFIRMATION REQUIRED
=======================================================
  REORDER: move policy 4 before policy 3
=======================================================
  Type 'yes' to confirm or 'no' to cancel.
```
**User:** yes  
**Agent:** 
```text
Policy 4 has been moved before policy 3.
[Verified current policy order:]
  ID   1 | LAN-Internet              | accept | port2 → port1
  ID   4 | test1                     | accept | port1 → port2
  ID   3 | BlockSSH                  | accept | port1 → port2
```

---

## 21. API / Tool Execution Flow

Tools (`modules/`) serve as raw, thin wrappers around `requests`. They do no reasoning. They accept strictly typed arguments, execute the REST payload, and return normalized JSON dictionaries. The `AgentSession` invokes these tools dynamically via `executor.py` based on the grounded schema.

---

## 22. Logging & Auditability

All operations are permanently logged to `logs/audit.jsonl`.
* Records User Intent, Pre-State, Execution Status, and Delta.
* Computes a rolling SHA-256 hash chaining system, making the log file tamper-evident for security audits.

---

## 23. Future Roadmap

- **Create Rollback Support**: Expanding `snapshot.py` to support `OperationType.CREATE` for automated deletion of rolled-back resources.
- **REST API Resiliency**: Implementing `urllib3` retry adapters for exponential backoff during high network latency.
- **Role-Based Access Control (RBAC)**: Enforcing strict user privileges matching FortiOS admin profiles.
- **SIEM Integration**: Forwarding audit logs to external platforms for automated incident response.

---

## 24. Design Principles

1. **Principle of Least Privilege**: The LLM cannot execute code.
2. **Immutable Traceability**: Every write action leaves a permanent footprint.
3. **Graceful Degradation**: If an API fails, the application fails safely, clears pending states, and alerts the user.

---

## 25. Production Considerations

When deploying to a production enterprise environment:
* Change `VERIFY_SSL = True` and load appropriate CA certificates.
* Isolate `AgentSession` state to dedicated user threads to support multi-tenant concurrency.
* Secure the Streamlit interface behind a reverse proxy (NGINX/Traefik) with OIDC/SAML authentication.

---

## 26. Known Limitations

* **Rollback of CREATES**: Currently, deleting a newly created policy via rollback requires manual intervention.
* **VM Licensing Limits**: If running against a FortiGate VM trial, maximum policy limits (typically 3) will artificially restrict agent creation commands.

---

## 27. Contributing

Contributions are welcome to expand the REST module coverage (e.g., IPsec VPN creation, SD-WAN rules). Please ensure all new modules are fully mapped in `nlu_schema.py` and strict rollback functions are provided in `snapshot.py`.

---

## 28. License

Distributed under the MIT License. See `LICENSE` for more information.

---

## 29. Author / Credits

Developed as a capstone engineering project (PFE).  
**Architecture & Implementation**: [Rhayem Saidi](https://github.com/RhayemSaidi)  
**Powered By**: Mistral AI, Fortinet, Streamlit, LangChain
