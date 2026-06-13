# 🧪 AegisFlow: Security Test Datasets

Use these sample datasets to copy-paste into your AegisFlow workspace. These indicators have been selected to trigger correct threat levels in **Sandbox Mode** (no API keys) and will perform lookups normally if **Live Keys** are active.

---

## 🔍 Part 1: IOC Log Triage Data

### A. Malicious Log Snippet (Produces 1 Malicious Hash, 1 Malicious URL, 1 Suspicious IP)
Paste this log into the **LOG BRIEF INPUT** and click **EXTRACT & ENRICH**:

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

* **Expected Sandbox Output**:
  * `275a021bcfb64891...` (SHA256 Hash): **Malicious (75%)**
  * `http://banking-auth-secure.net/...` (URL): **Malicious (71%)**
  * `198.51.100.45` (IP Address): **Suspicious (47%)**

---

### B. Clean Log Snippet (Produces 1 Clean IP, 1 Clean Domain)
Paste this log into the **LOG BRIEF INPUT** and click **EXTRACT & ENRICH**:

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

* **Expected Sandbox Output**:
  * `12.12.12.12` (IP Address): **Safe (0%)**
  * `example.com` (Domain): **Safe (0%)** (Note: `example.com` is whitelisted by default to ensure standard domains are automatically filtered out unless they are explicitly searched).

---

## 📧 Part 2: Phishing Email Header Data

### A. Suspicious / Spoofed Email Header (Produces SPF/DKIM/DMARC Fails and Suspicious Hops)
Paste these headers into the **PHISHING HEADER INPUT** and click **AUDIT SMTP ROUTE**:

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

* **Expected Sandbox Output**:
  * **SPF Check**: **FAIL**
  * **DKIM Check**: **FAIL**
  * **DMARC Check**: **FAIL**
  * **SPF Alignment**: **MISALIGNED** (PayPal vs PayPal-Update)
  * **Hops**: Highlights `mail.suspiciousrelay.com` as a suspicious relay node.

---

### B. Clean / Verified Email Header (Produces SPF/DKIM/DMARC Passes and Clean Hops)
Paste these headers into the **PHISHING HEADER INPUT** and click **AUDIT SMTP ROUTE**:

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

* **Expected Sandbox Output**:
  * **SPF Check**: **PASS**
  * **DKIM Check**: **PASS**
  * **DMARC Check**: **PASS**
  * **SPF Alignment**: **ALIGNED** (Both domains match `google.com`)
  * **Hops**: Renders green, clean server transmission pathways.
