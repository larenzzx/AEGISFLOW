# 🧪 AegisFlow: Step-by-Step Triage & Testing Tutorial

This guide walks you through verifying AegisFlow's features using carefully selected test datasets. It shows you exactly what to copy, where to paste it, and what features to check.

---

## 🧭 Test Case 1: Triage Malicious Incident Logs

This test case demonstrates how AegisFlow automatically extracts IP addresses, server domains, file hashes, and URL endpoints from dirty logs, resolves their threat scores, renders a correlation map, and designs block playbooks.

### Step-by-Step Instructions:
1. Open the application.
2. In the left navigation sidebar, click on **IOC LOG TRIAGE**.
3. Copy the entire raw log box below:

```text
CRITICAL SEC_ALERT: Malware Executable Detected
Severity: HIGH
Hostname: Fin-Client-104
Action: Session Terminated

Log Summary:
Host attempted access to suspicious external download server:
- Destination URL: http://banking-auth-secure.net/login.php
- Destination IP Address: 198.51.100.45
- Local Executable File Signature SHA256: 275a021bcfb648915565ed19c297908b1fe69466544e999c15e8a56d8174120a

Remediation:
Host isolation initiated. Please check reputation status and apply block scripts.
```

4. Paste this text block into the **LOG BRIEF INPUT** text area on the left.
5. Click the green **EXTRACT & ENRICH** button.

### 🔍 What to Look For:
* **The Loading Modal**: A circular neon check loader titled `SYSTEM ANALYZING` will appear, showing that AegisFlow is parsing the indicators.
* **The Success Alert**: Once done, a dialog titled `Triage Complete` will pop up summarizing the count of discovered malicious elements. Click **CONFIRM** to dismiss it.
* **The Dashboard History**: If you navigate back to **DASHBOARD OVERVIEW**, you will see a new entry logged under **Recent Investigations** with the status `1 Malicious / 2 Warn`.
* **Telemetry Inspector**: In the **IOC Log Triage** page, look at the **Extracted Indicators** list on the right:
  * Click on the row containing hash `275a021bcfb...` to see VirusTotal scanner engine hits and OTX tags in the **Telemetry Detail** inspector card.
  * Click on IP `198.51.100.45` to see its geo-location country code and AbuseIPDB report stats.
* **The Threat Canvas**: Click **THREAT CANVAS** in the sidebar. You will see a structural relation map linking the Central Incident to the IP, the domain, the URL, and the malicious hash. Click any circle to inspect it.
* **The AI Playbook**: Click **AI PLAYBOOKS** in the sidebar. AegisFlow has generated Palo Alto address rules, Fortinet CLI configurations, Suricata drop commands, Splunk SIEM queries, and a written report summary. Click **COPY** to copy any script, or **EXPORT REPORT** to download the text.

---

## 🧭 Test Case 2: Triage Clean Event Logs

This test case verifies how the triage dashboard handles standard/safe telemetry traffic and filters out whitelisted entries.

### Step-by-Step Instructions:
1. Go to the **IOC LOG TRIAGE** workspace page.
2. Clear the input box and copy the clean log block below:

```text
INFO SEC_MONITOR: Standard API Handshake
Severity: LOW
Hostname: API-Gateway-Prod-01

Log Summary:
Internal application completed an API request to safe external service:
- Endpoint: 12.12.12.12
- Domain target: example.com

Telemetry:
Bytes Transferred: 1042 bytes.
Connection State: Closed.
```

3. Paste this into the **LOG BRIEF INPUT** box.
4. Click the green **EXTRACT & ENRICH** button.

### 🔍 What to Look For:
* **Whitelisting filter**: Notice that target domain `example.com` is automatically ignored because it is whitelisted by default in the parser, leaving only the IP `12.12.12.12` to be analyzed.
* **Safe Status**: Discovered IP `12.12.12.12` will show as **Clean / Safe (0% reputation score)**.
* **Clean Canvas**: The Threat Canvas will draw safe green indicators.

---

## 🧭 Test Case 3: Audit Phishing Email Headers (Spoofed Mail)

This test case runs SPF, DKIM, and DMARC alignment validation checks, parses envelope mismatches, and draws the chronological server journey of a spoofed email.

### Step-by-Step Instructions:
1. In the left navigation sidebar, click on **PHISHING ROUTING**.
2. Copy the email header block below:

```text
Delivered-To: recipient@company.com
Received: from mail.suspiciousrelay.com (mail.suspiciousrelay.com [198.51.100.45])
        by mx.google.com with ESMTPS id q18si12093551plj.8.2026.06.13.01.10.00
        for <recipient@company.com>;
        Sat, 13 Jun 2026 01:10:00 -0700 (PDT)
Received-SPF: fail (google.com: domain of sender@paypal-update.net does not designate 198.51.100.45 as permitted sender) client-ip=198.51.100.45;
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of sender@paypal-update.net does not designate 198.51.100.45 as permitted sender) smtp.mailfrom=sender@paypal-update.net;
       dkim=fail header.i=@paypal-update.net;
       dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE) header.from=paypal.com
From: "PayPal Help" <support@paypal.com>
Return-Path: <sender@paypal-update.net>
Subject: Action Required: Verify your credentials
Date: Sat, 13 Jun 2026 01:05:00 -0700
```

3. Paste this block into the **PHISHING HEADER INPUT** text area.
4. Click the blue **AUDIT SMTP ROUTE** button.

### 🔍 What to Look For:
* **The Loading Modal**: A circular blue analysis modal will appear for `1.2 seconds` as the server relay hops are extracted and ordered chronologically.
* **Success Alert**: Click **CONFIRM** when the pop-up modal finishes.
* **Authentication Fail Badges**: In the **SMTP Authentications** panel, notice that **SPF**, **DKIM**, and **DMARC** all show red `FAIL` badges, and the alignment report displays **MISALIGNED** (since the envelope sender `paypal-update.net` tries to spoof `paypal.com`).
* **Relay Hops Timeline**: Look at the **SMTP Transmission Path** timeline. It maps the delivery path starting from the original sender and highlights the relay hop `mail.suspiciousrelay.com` in red as a **SUSPICIOUS** relay node.
* **SMTP Anomaly Audit**: The console card lists security anomalies (e.g. envelope mismatches and unauthorized server IPs).

---

## 🧭 Test Case 4: Audit Clean Email Headers

This test case verifies how AegisFlow displays fully authenticated and aligned headers from secure server relays.

### Step-by-Step Instructions:
1. Go to the **PHISHING ROUTING** workspace page.
2. Clear the input box and copy the clean header block below:

```text
Delivered-To: recipient@company.com
Received: from mail-sor-f69.google.com (mail-sor-f69.google.com [209.85.220.69])
        by mx.google.com with ESMTPS id b12si14890835pfr.224.2026.06.13.01.15.00
        for <recipient@company.com>;
        Sat, 13 Jun 2026 01:15:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of support@google.com designates 209.85.220.69 as permitted sender) client-ip=209.85.220.69;
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of support@google.com designates 209.85.220.69 as permitted sender) smtp.mailfrom=support@google.com;
       dkim=pass header.i=@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
From: "Google Workspace" <support@google.com>
Return-Path: <support@google.com>
Subject: Google Workspace Security Update
Date: Sat, 13 Jun 2026 01:12:00 -0700
```

3. Paste this into the **PHISHING HEADER INPUT** box.
4. Click the blue **AUDIT SMTP ROUTE** button.

### 🔍 What to Look For:
* **Pass Badges**: **SPF**, **DKIM**, and **DMARC** show green `PASS` badges, and SPF alignment shows **ALIGNED** (matching domains).
* **Safe Relay Nodes**: Renders safe, green timeline relays.
