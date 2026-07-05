<div align="center">


<img width="400" height="400" alt="12" src="https://github.com/user-attachments/assets/5b5f2526-6488-422f-8394-f97de852b2e9" />

# ASTRA

### Autonomous Security Threat Research Agent

**Recon • Hunt • Analyze • Validate • Report**

</div>


# What Is This?

Astra is an AI-powered bug bounty hunting agent that runs on Kali Linux. You give it a domain, it does everything — subdomain enumeration, live host discovery, crawling, and then runs 25 automated vulnerability classes against the target. Every finding gets fed to an AI model that triages it, estimates bounty value, builds attack chains, and writes submission-ready reports.

```text
 █████╗ ███████╗████████╗██████╗  █████╗
██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
███████║███████╗   ██║   ██████╔╝███████║
██╔══██║╚════██║   ██║   ██╔══██╗██╔══██║
██║  ██║███████║   ██║   ██║  ██║██║  ██║
╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝

        Autonomous Security Threat Research Agent

        Recon • Hunt • Analyze • Validate • Report
```

---

# 📁 Files - What Each One Does

The ASTRA project is designed with a modular architecture that separates the AI engine, reconnaissance pipeline, vulnerability detection, memory management, reporting, and frontend into dedicated components.

| File / Folder | Approx. Size | Description |
|---------------|-------------|-------------|
| **app.py** | ~350 LOC | Main Flask application responsible for routing, REST APIs, WebSocket communication, session management, and coordinating all backend modules. |
| **brain.py** | ~220 LOC | AI Intelligence Engine supporting multiple LLM providers including Ollama, OpenAI, Claude, Groq, Gemini, and DeepSeek with automatic provider detection and streaming responses. |
| **tools.py** | ~900 LOC | Core Security Engine containing reconnaissance modules, vulnerability scanners, attack automation, validation logic, and report generation workflows. |
| **memory.py** | ~80 LOC | Persistent Hunt Memory built on JSONL storage for maintaining scan history, AI conversations, findings, and reusable reconnaissance knowledge across sessions. |
| **index.html** | ~1,100 LOC | Interactive Dashboard featuring a modern WebSocket-powered interface with real-time scan progress, AI chat, findings explorer, reporting tools, and analytics panels. |
| **run.sh** | ~25 LOC | Startup script that initializes the Python virtual environment, loads configuration, starts optional AI services (Ollama), and launches the ASTRA server. |
| **install_tools.sh** | ~50 LOC | Automated installer for external reconnaissance and security tools using Go, Python, and APT package managers. |
| **recon/** | Directory | Stores reconnaissance artifacts such as discovered subdomains, live hosts, crawled URLs, JavaScript files, Nuclei scan results, screenshots, and findings for each target. |
| **reports/** | Directory | Contains automatically generated vulnerability reports in Markdown format, organized by target and timestamp. |
| **memory/** | Directory | Persistent storage for hunt memory, previous AI analyses, session history, and cached reconnaissance data. |
| **venv/** | Directory | Python virtual environment containing ASTRA's runtime dependencies and installed packages. |

---

# 🤖 AI Models & Provider System

ASTRA features a flexible multi-provider AI engine powered by **brain.py**, allowing seamless switching between local and cloud-based Large Language Models (LLMs). The system automatically detects available providers, supports real-time streaming responses, and falls back to the next provider if one is unavailable.

## 🔄 Provider Priority

| Priority | Provider | Type | Cost | Best For |
|----------|----------|------|------|----------|
| ① | Ollama | Local | Free | Offline & Privacy |
| ② | Groq | Cloud | Free Tier | Fast Inference |
| ③ | DeepSeek | Cloud | Low Cost | Bulk Analysis |
| ④ | Claude | Cloud | Premium | Advanced Reasoning |
| ⑤ | OpenAI | Cloud | Premium | General AI Tasks |
| ⑥ | Gemini | Cloud | Free Tier | Backup Provider |

> Preferred provider can be selected from the Settings page or using the `ASTRA_PROVIDER` environment variable.

## ✨ Features

- Automatic provider detection & failover
- Real-time streaming responses
- Live provider switching
- Automatic API key loading
- Local and cloud AI support
- Zero configuration fallback system

## 🌐 Streaming

All supported providers stream responses in real time using Server-Sent Events (SSE) and WebSockets, allowing the dashboard to display AI output instantly as it is generated.

---

# 🛡️ Vulnerability Detection

ASTRA's Hunt Engine combines automated security tools with intelligent HTTP-based testing to detect a wide range of web application vulnerabilities. Every finding is validated, deduplicated, and prioritized by severity before being presented in the dashboard.

## 🎯 Supported Vulnerability Classes

| Severity | Vulnerability | Detection Method |
|----------|---------------|------------------|
| 🔴 Critical | SQL Injection | SQLMap + custom payload testing |
| 🔴 Critical | Cross-Site Scripting (XSS) | Reflected, Stored & DOM XSS detection |
| 🔴 Critical | Server-Side Request Forgery (SSRF) | Parameter & metadata endpoint testing |
| 🔴 Critical | Local File Inclusion (LFI) | Path traversal payloads |
| 🔴 Critical | Command Injection | OS command execution payloads |
| 🔴 Critical | SSTI / Remote Code Execution | Template engine payloads |
| 🔴 Critical | XML External Entity (XXE) | XML entity injection |
| 🔴 Critical | JavaScript Secret Exposure | API keys, tokens & credentials |
| 🟠 High | CORS Misconfiguration | Origin validation & header analysis |
| 🟠 High | IDOR / BOLA | Authorization & object access testing |
| 🟠 High | Authentication Bypass | Login & access control checks |
| 🟠 High | Open Redirect | Redirect parameter validation |
| 🟠 High | Subdomain Takeover | Cloud service fingerprinting |
| 🟠 High | GraphQL Security | Introspection & endpoint testing |
| 🟠 High | JWT Vulnerabilities | Token analysis & weak configuration checks |
| 🟠 High | CRLF Injection | HTTP response splitting |
| 🟠 High | Cache Poisoning | Host header injection |
| 🟡 Medium | Sensitive File Exposure | Common backup & configuration files |
| 🟡 Medium | Missing Security Headers | Security header validation |
| 🟡 Medium | Rate Limiting Issues | Request throttling detection |
| 🟡 Medium | Dangerous HTTP Methods | PUT, DELETE, TRACE & more |
| 🟡 Medium | Information Disclosure | Version & error leakage |
| 🟡 Medium | CMS Security Checks | WordPress, Laravel, Drupal, etc. |
| 🟡 Medium | WAF Detection | Firewall fingerprinting |
| 🟡 Medium | Nuclei Template Scan | 9,000+ community templates |

> **Total Coverage: 25+ Web Application Vulnerability Classes**

---

# 🔧 Integrated Security Tools

ASTRA integrates industry-standard open-source security tools to automate reconnaissance, scanning, crawling, fuzzing, and vulnerability detection. Each tool is optional—missing tools are skipped automatically without interrupting the workflow.

| Tool | Purpose |
|------|---------|
| Subfinder | Subdomain enumeration |
| Httpx | Live host discovery & technology detection |
| Nuclei | Template-based vulnerability scanning |
| Katana | Web crawling & endpoint discovery |
| Dalfox | XSS detection |
| SQLMap | SQL Injection testing |
| DNSX | DNS validation & resolution |
| GAU | Historical URL collection |
| FFUF | Directory & endpoint fuzzing |
| Gobuster | Content & DNS brute-forcing |
| Nmap | Port & service discovery |
| Amass | Advanced asset enumeration |
| Nikto | Web server security assessment |
| WhatWeb | Technology fingerprinting |
| Arjun | Hidden parameter discovery |
| Feroxbuster | Recursive content discovery |
| cURL | HTTP request fallback engine |

> **17+ Integrated Security Tools working together to provide comprehensive reconnaissance and vulnerability assessment.**

---

# 🚀 Hunt Workflow

ASTRA supports both fully automated and manual guided security assessments, allowing researchers to choose the workflow that best fits their engagement.

## 🤖 Autopilot Mode

The complete reconnaissance and vulnerability assessment pipeline runs automatically in three stages.

| Phase | Description |
|--------|-------------|
| 🔍 Reconnaissance | Asset discovery, live host detection, URL crawling, JavaScript analysis, port scanning, and initial vulnerability checks. |
| 🎯 Vulnerability Hunt | Executes all 25 vulnerability detection modules, validates findings, removes duplicates, and prioritizes results by severity. |
| 📝 AI Analysis & Reporting | AI analyzes findings, generates executive summaries, attack chains, remediation advice, and professional bug bounty reports. |

## 👨‍💻 Manual Guided Mode

For researchers who prefer complete control over the testing process.

- Set the target domain
- Configure authentication (Cookies / Bearer Tokens)
- Run reconnaissance
- Analyze findings with AI
- Launch vulnerability scans
- Validate findings
- Generate and enhance reports
- Submit to your preferred bug bounty platform

---

# 🚀 Installation & Setup

## 📦 Initial Installation

```bash
# Clone the repository
git clone https://github.com/Omchaudhari73/astra/
cd astra

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r backend/requirements.txt

# Install external security tools
chmod +x install_tools.sh
./install_tools.sh

# Launch ASTRA
python3 app.py
```

---

# 🔧 Troubleshooting

| Issue | Solution |
|-------|----------|
| WebSocket connection fails | Install eventlet and restart ASTRA |
| AI provider not detected | Verify API keys or ensure Ollama is running |
| Security tool missing | Re-run `./install_tools.sh` |
| Permission denied | Run `chmod +x *.sh` before executing scripts |

---

# ⚖️ Legal Notice

> ASTRA is intended exclusively for authorized security testing. Only scan systems you own or have explicit permission to assess through bug bounty programs, penetration testing engagements, or written authorization. Users are responsible for complying with all applicable laws and program policies.

---

# 📬 Contact

- ℹ️ **Linkdin:** www.linkedin.com/in/omchaudhari7385 
- 📧 **Email:** chaudhariom360@gmail.com

---

<div align="center">

### Developed with ❤️ for the Cybersecurity Community

**Built by bug hunters, for bug hunters.**

**MIT License • Responsible Disclosure • Authorized Security Testing Only**

</div>
