# 🛡️ AegisFlow: SOC Threat Intelligence & Phishing Auditing Dashboard

AegisFlow is a high-density, cyberpunk-styled cybersecurity command center designed for **Security Operations Center (SOC) Analysts**. Its primary purpose is to address **"dashboard fatigue"** by unifying multiple external threat databases, log parsers, and email header forensic tools into a single responsive panel.

---

## 🎯 Purpose and Intent
When an alert fires, analysts often spend valuable minutes switching between different lookup portals (VirusTotal, AbuseIPDB, AlienVault) to collect IP, domain, hash, or URL reputations, and tracing SMTP server headers by hand to verify sender alignment.

**AegisFlow automates this entire lookup lifecycle:**
1. It automatically extracts indicators of compromise (IOCs) from dirty logs using robust regex pattern matching.
2. It queries active reputation scoring databases concurrently.
3. It maps the topological relationships of the indicators in an interactive Threat Canvas.
4. It compiles Palo Alto and Fortinet firewall block commands, Suricata network rule drop scripts, Splunk hunt lookups, and executive reports instantly.

---

## 🧭 Key Features

### 1. 🔍 IOC Log Triage Workspace
* Paste raw log buffers, firewall notifications, or list of indicators into the input area.
* Extract domains, IP addresses, URL links, and cryptographic file hashes (MD5, SHA1, SHA256) automatically.
* Query active engines concurrently for reputations (VirusTotal, AbuseIPDB, AlienVault OTX tags).
* Click any row in the indicators table to populate a dedicated telemetry details panel.

### 2. 📧 Phishing Routing Auditor
* Paste raw SMTP email header blocks.
* Color-coded authentication badges display status for **SPF**, **DKIM**, and **DMARC** validation checks.
* Evaluates envelope domains against the headers to flag DKIM and SPF misalignments.
* Parses and chronologically reverses the `Received` header headers to trace the hop-by-hop journey of the email, flagging dynamic IP ranges and suspicious email relays in red.

### 3. 🕸️ Interactive Threat Canvas
* Renders a real-time SVG topology chart showing connections between the main incident, IP nodes, domain name queries, URL targets, and file signature hashes.
* Highlights nodes by severity level (Green: Safe, Yellow: Suspicious, Red: Malicious).
* Interactive nodes pop open a floating inspector overlay on hover or click.

### 4. 📝 Automated containment playbooks
* Palo Alto networks CLI block commands generator.
* Fortinet firewall CLI network address definitions generator.
* Suricata / Snort intrusion detection system rule outputs.
* Splunk SIEM search query generator.
* NIST protocols markdown executive report template.
* Instantly export and download a compiled report file.

### 5. 📂 Persistent History Cache & Logging
* Auto-saves log analyses, header audits, and configuration settings in browser local storage.
* Stores up to 100 history items. Clicking any history row in the Dashboard Overview restores its entire workspace state.
* Individual row delete buttons are protected with click event propagation overrides.
* **Cortex Activity Console**: A terminal-style console logging session operations in real time (e.g. key updates, threat scans, draft saves, and row deletions).

---

## 🛠️ Technology Stack
* **Vite + React 19**
* **TypeScript** (compiled in strict compliance mode)
* **Tailwind CSS v4** (integrated directly into the Vite build engine)
* **Lucide React** (icons)
* **shadcn/ui** primitives (built on Radix UI)

---

## 📂 Codebase Structure
* [src/App.tsx](file:///C:/Users/markl/aegisflow/src/App.tsx): Main dashboard shell layout containing view routers, state variables, table rows, layouts, SVG drawing components, and configuration settings.
* [src/lib/threatService.ts](file:///C:/Users/markl/aegisflow/src/lib/threatService.ts): Contains extraction regex models, active API request queries for VirusTotal API v3, AbuseIPDB API v2, AlienVault OTX API v1, SMTP chronological parser, and simulated backup mock datasets.
* [src/index.css](file:///C:/Users/markl/aegisflow/src/index.css): CSS variables, CRT scanlines animation filters, scrollbar parameters, and custom neon glow aesthetics.
