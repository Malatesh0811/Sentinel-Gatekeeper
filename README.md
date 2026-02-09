# 🛡️ Sentinel Gatekeeper
> **Context-Aware DevSecOps Policy Engine**

![Sentinel Dashboard](https://via.placeholder.com/800x400.png?text=Upload+Your+Screenshot+Here)

## 🚀 The Problem
Traditional security scanners (SAST/SCA) suffer from **Alert Fatigue**. They flag every vulnerability found, regardless of whether it is actually exploitable.
* **Example:** A critical vulnerability in a library that is only used by an internal admin tool, hidden behind a firewall.
* **Result:** Developers ignore security alerts because 90% are false positives.

## 💡 The Solution
**Sentinel** is a graph-based policy engine that introduces **Reachability Analysis** to the CI/CD pipeline.
1.  **Parses Source Code (AST):** Builds a call graph of the application.
2.  **Maps Infrastructure:** Identifies public API endpoints vs. private internal routes.
3.  **Correlates Vulnerabilities:** Only blocks deployment if a vulnerability is reachable from the public internet.

## 🛠️ Tech Stack
* **Engine:** Python 3.12 (AST, NetworkX)
* **Scanners:** Trivy (Dependencies), Semgrep (SAST)
* **Visualization:** Cytoscape.js
* **Containerization:** Docker (Debian Slim)
* **Architecture:** REST API (FastAPI)

## ⚡ How to Run
### Option 1: Docker (Recommended)
```bash
docker run -p 8000:8000 yourusername/sentinel-gatekeeper


### 📸 Screenshots

### 🛡️ Live Security Dashboard
*Real-time visualization of your application's architecture and security status.*
![Live Dashboard](screenshots/dashboard.png)

### 🕸️ Attack Graph Visualization
*Dynamically maps "Internet" -> "Public Route" -> "Vulnerable Function" to detect exploit paths.*
![Attack Graph](screenshots/graph.png)

### ⛔ Blocked Deployment
*The engine automatically blocks the build when a Critical Vulnerability is found on a Public Route.*
![Blocked Deployment](screenshots/logs.png)
