import { useState, useEffect } from "react";
import { 
  ShieldAlert, Settings, Terminal, Share2, Clipboard, Download, 
  Globe, Hash, Link as LinkIcon, Play, Server, AlertTriangle, RefreshCw, X,
  Info, Copy, Check, Home, Mail, FileText, Activity, Clock, Trash2
} from "lucide-react";

import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";

import { extractIOCs, enrichIndicator, parseEmailHeaders } from "@/lib/threatService";
import type { ThreatReport, PhishingHeaderReport, ApiKeys } from "@/lib/threatService";

type NavigationSection = "overview" | "triage" | "phishing" | "graph" | "playbook" | "settings";

interface IncidentHistoryItem {
  id: string;
  timestamp: string;
  type: "triage" | "phishing";
  inputExcerpt: string;
  inputText: string;
  reports: ThreatReport[];
  phishingReport: PhishingHeaderReport | null;
  maliciousCount: number;
  warningsCount: number;
}

export default function App() {
  const [currentSection, setCurrentSection] = useState<NavigationSection>("overview");
  const [inputText, setInputText] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  
  // Threat Indicators State
  const [threatReports, setThreatReports] = useState<ThreatReport[]>([]);
  const [selectedReport, setSelectedReport] = useState<ThreatReport | null>(null);
  
  // Phishing Header State
  const [headerText, setHeaderText] = useState("");
  const [phishingReport, setPhishingReport] = useState<PhishingHeaderReport | null>(null);
  
  // API Keys Config State
  const [apiKeys, setApiKeys] = useState<ApiKeys>({
    virusTotal: "",
    abuseIPDB: "",
    alienVaultOTX: ""
  });
  
  // History list state
  const [incidentHistory, setIncidentHistory] = useState<IncidentHistoryItem[]>([]);
  
  // Activity Console log state
  const [activityLogs, setActivityLogs] = useState<Array<{ timestamp: string; message: string; type: "info" | "warning" | "success" | "danger" }>>([]);

  const addActivityLog = (message: string, type: "info" | "warning" | "success" | "danger" = "info") => {
    const newLog = {
      timestamp: new Date().toLocaleTimeString(),
      message,
      type
    };
    setActivityLogs(prev => {
      const updated = [newLog, ...prev].slice(0, 50);
      localStorage.setItem("aegisflow_activity_logs", JSON.stringify(updated));
      return updated;
    });
  };
  
  // Graph Canvas nodes state
  const [selectedNode, setSelectedNode] = useState<{ id: string; type: string; label: string; data?: any } | null>(null);
  
  // Dialog Open States
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [copiedIndicator, setCopiedIndicator] = useState<string | null>(null);
  const [showKeyWarning, setShowKeyWarning] = useState(false);
  const [warningCallback, setWarningCallback] = useState<{ action: () => void } | null>(null);

  const [successModalOpen, setSuccessModalOpen] = useState(false);
  const [successModalContent, setSuccessModalContent] = useState({ title: "", message: "" });
  const [analysisLoadingOpen, setAnalysisLoadingOpen] = useState(false);
  const [analysisLoadingMessage, setAnalysisLoadingMessage] = useState("");

  const [deleteConfirmationOpen, setDeleteConfirmationOpen] = useState(false);
  const [itemToDelete, setItemToDelete] = useState<string | null>(null);
  const [clearConfirmationOpen, setClearConfirmationOpen] = useState(false);

  const triggerSuccessModal = (title: string, message: string) => {
    setSuccessModalContent({ title, message });
    setSuccessModalOpen(true);
  };

  const isSimulatedMode = !apiKeys.virusTotal && !apiKeys.abuseIPDB && !apiKeys.alienVaultOTX;

  // Sample data templates
  const SAMPLE_LOG = `LOG ANALYSIS ALERT: Possible Incident Detected
Timestamp: 2026-06-13T01:10:00Z
Source Host: Internal-Webserver-Prod
Alert Trigger: Suspicious outbound connection to remote endpoint.

Details:
The server detected an outgoing HTTP POST request to suspicious external host:
- Remote Target: http://banking-auth-secure.net/login.php
- Resolved Host IP: 198.51.100.45
- Local Process SHA256: 275a021bcfb648915565ed19c297908b1fe69466544e999c15e8a56d8174120a

Secondary events:
DNS query failed for domain: paypal-security-update.support
Internal DNS resolver received a request from host 203.0.113.19.
Whitelist verification requested for internal DNS 8.8.8.8.
Please triage immediately.`;

  const SAMPLE_EMAIL = `Delivered-To: recipient@company.com
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
Date: Sat, 13 Jun 2026 01:05:00 -0700`;

  // Load API Keys, History and Logs from LocalStorage on mount
  useEffect(() => {
    const savedKeys = localStorage.getItem("aegisflow_keys");
    if (savedKeys) {
      try {
        setApiKeys(JSON.parse(savedKeys));
      } catch (e) {
        console.error("Failed to parse API keys", e);
      }
    }

    const savedHistory = localStorage.getItem("aegisflow_history");
    if (savedHistory) {
      try {
        setIncidentHistory(JSON.parse(savedHistory));
      } catch (e) {
        console.error("Failed to parse history", e);
      }
    }

    const savedLogs = localStorage.getItem("aegisflow_activity_logs");
    if (savedLogs) {
      try {
        setActivityLogs(JSON.parse(savedLogs));
      } catch (e) {
        console.error("Failed to parse activity logs", e);
      }
    } else {
      const initialLogs = [
        { timestamp: new Date().toLocaleTimeString(), message: "System initialized. Sandbox mode active.", type: "warning" as const },
        { timestamp: new Date().toLocaleTimeString(), message: "Secure cortex connection established.", type: "success" as const }
      ];
      setActivityLogs(initialLogs);
      localStorage.setItem("aegisflow_activity_logs", JSON.stringify(initialLogs));
    }
  }, []);

  const saveKeys = (keys: ApiKeys) => {
    localStorage.setItem("aegisflow_keys", JSON.stringify(keys));
    setApiKeys(keys);
    setSettingsOpen(false);
    addActivityLog("Threat Intelligence API key configurations updated.", "success");
    triggerSuccessModal("API Keys Configured", "Your threat intelligence API keys have been saved successfully. AegisFlow is now configured to fetch live reputation metrics.");
  };

  // Trigger IOC Extraction and enrichment (with API key check)
  const handleTriage = () => {
    if (!inputText.trim()) return;
    if (isSimulatedMode) {
      setWarningCallback({
        action: () => {
          setShowKeyWarning(false);
          runTriageScan();
        }
      });
      setShowKeyWarning(true);
    } else {
      runTriageScan();
    }
  };

  const runTriageScan = async () => {
    addActivityLog("Executing IOC Log Triage audit...", "info");
    setAnalysisLoadingMessage("Parsing payload and querying reputation datasets...");
    setAnalysisLoadingOpen(true);
    setIsProcessing(true);
    setSelectedReport(null);
    setSelectedNode(null);
    
    const iocs = extractIOCs(inputText);
    const listToEnrich: Array<{ value: string; type: "ip" | "domain" | "hash" | "url" }> = [
      ...iocs.ips.map(ip => ({ value: ip, type: "ip" as const })),
      ...iocs.domains.map(dom => ({ value: dom, type: "domain" as const })),
      ...iocs.hashes.map(hash => ({ value: hash, type: "hash" as const })),
      ...iocs.urls.map(url => ({ value: url, type: "url" as const }))
    ];

    try {
      const reports = await Promise.all(
        listToEnrich.map(item => enrichIndicator(item.value, item.type, apiKeys))
      );
      setThreatReports(reports);
      
      const mal = reports.filter(r => r.status === "malicious").length;
      const susp = reports.filter(r => r.status === "suspicious").length;
      const safe = reports.filter(r => r.status === "safe").length;
      
      if (reports.length > 0) {
        setSelectedReport(reports[0]);
      }

      // Add to session history
      const newIncident: IncidentHistoryItem = {
        id: `INC-${Date.now().toString().slice(-6)}`,
        timestamp: new Date().toLocaleString(),
        type: "triage",
        inputExcerpt: inputText.substring(0, 60) + "...",
        inputText: inputText,
        reports,
        phishingReport: null,
        maliciousCount: mal,
        warningsCount: susp
      };
      
      const updatedHistory = [newIncident, ...incidentHistory].slice(0, 100);
      setIncidentHistory(updatedHistory);
      localStorage.setItem("aegisflow_history", JSON.stringify(updatedHistory));
      
      addActivityLog(`IOC Triage complete: analyzed ${reports.length} indicators.`, "success");
      if (mal > 0) {
        addActivityLog(`ALERT: ${mal} malicious indicators detected on host!`, "danger");
      }

      setAnalysisLoadingOpen(false);
      triggerSuccessModal(
        "Triage Complete",
        `IOC Log Triage finished successfully. Discovered ${mal} malicious files/hosts, ${susp} warnings, and ${safe} clean indicators.`
      );
    } catch (err) {
      console.error("Enrichment failed", err);
      addActivityLog("IOC Enrichment query failed.", "danger");
      setAnalysisLoadingOpen(false);
      triggerSuccessModal("Triage Failed", "Indicator lookup encountered a connection or query parsing error.");
    } finally {
      setIsProcessing(false);
    }
  };

  // Trigger Phishing Header Analysis (with API key check)
  const handleParseHeaders = () => {
    if (!headerText.trim()) return;
    if (isSimulatedMode) {
      setWarningCallback({
        action: () => {
          setShowKeyWarning(false);
          runParseHeaders();
        }
      });
      setShowKeyWarning(true);
    } else {
      runParseHeaders();
    }
  };

  const runParseHeaders = () => {
    addActivityLog("Executing SMTP Routing pathway audit...", "info");
    setAnalysisLoadingMessage("Reconstructing server relay timeline and auditing alignments...");
    setAnalysisLoadingOpen(true);
    setIsProcessing(true);

    setTimeout(() => {
      try {
        const report = parseEmailHeaders(headerText);
        setPhishingReport(report);
        
        const mal = report.verdict === "malicious" ? 1 : 0;
        const susp = report.verdict === "suspicious" ? 1 : 0;

        const newIncident: IncidentHistoryItem = {
          id: `INC-${Date.now().toString().slice(-6)}`,
          timestamp: new Date().toLocaleString(),
          type: "phishing",
          inputExcerpt: headerText.substring(0, 60) + "...",
          inputText: headerText,
          reports: [],
          phishingReport: report,
          maliciousCount: mal,
          warningsCount: susp
        };
        
        const updatedHistory = [newIncident, ...incidentHistory].slice(0, 100);
        setIncidentHistory(updatedHistory);
        localStorage.setItem("aegisflow_history", JSON.stringify(updatedHistory));

        addActivityLog(`SMTP Audit complete. SPF: ${report.spf.status} | DKIM: ${report.dkim.status} | DMARC: ${report.dmarc.status}`, report.verdict === "malicious" ? "danger" : report.verdict === "suspicious" ? "warning" : "success");
        
        setAnalysisLoadingOpen(false);
        triggerSuccessModal(
          "SMTP Audit Complete",
          `Email header audit finished. SPF: ${report.spf.status} | DKIM: ${report.dkim.status} | DMARC: ${report.dmarc.status}. Verdict: ${report.verdict.toUpperCase()}.`
        );
      } catch (e) {
        console.error("Phishing parsing failed", e);
        addActivityLog("SMTP Header analysis failed.", "danger");
        setAnalysisLoadingOpen(false);
        triggerSuccessModal("Audit Failed", "Failed to parse SMTP email headers. Please check form input.");
      } finally {
        setIsProcessing(false);
      }
    }, 1200);
  };

  // Clear Session History
  const clearHistory = () => {
    setClearConfirmationOpen(true);
  };

  const confirmClearHistory = () => {
    setIncidentHistory([]);
    localStorage.removeItem("aegisflow_history");
    addActivityLog("Triage incident history database cleared.", "warning");
    setClearConfirmationOpen(false);
    triggerSuccessModal("History Cleared", "All triaged logs, email audits, and session drafts have been successfully deleted.");
  };

  // Delete a specific history item
  const deleteHistoryItem = (id: string) => {
    setItemToDelete(id);
    setDeleteConfirmationOpen(true);
  };

  const confirmDeleteHistoryItem = (id: string) => {
    const updated = incidentHistory.filter(item => item.id !== id);
    setIncidentHistory(updated);
    localStorage.setItem("aegisflow_history", JSON.stringify(updated));
    addActivityLog(`Incident entry ${id} deleted from database.`, "warning");
    setDeleteConfirmationOpen(false);
    setItemToDelete(null);
    triggerSuccessModal("Incident Deleted", `Incident record ${id} was successfully removed from your history database.`);
  };

  // Save triage content as draft in history
  const handleSaveTriageDraft = () => {
    if (!inputText.trim()) return;
    const newIncident: IncidentHistoryItem = {
      id: `INC-${Date.now().toString().slice(-6)}`,
      timestamp: new Date().toLocaleString(),
      type: "triage",
      inputExcerpt: inputText.substring(0, 60) + "...",
      inputText: inputText,
      reports: [],
      phishingReport: null,
      maliciousCount: 0,
      warningsCount: 0
    };
    const updatedHistory = [newIncident, ...incidentHistory].slice(0, 100);
    setIncidentHistory(updatedHistory);
    localStorage.setItem("aegisflow_history", JSON.stringify(updatedHistory));
    addActivityLog(`Saved log draft ${newIncident.id} in history log.`, "success");
    triggerSuccessModal("Log Draft Saved", `Triage logs have been logged to dashboard history as ${newIncident.id}.`);
  };

  // Save phishing header content as draft in history
  const handleSavePhishingDraft = () => {
    if (!headerText.trim()) return;
    const newIncident: IncidentHistoryItem = {
      id: `INC-${Date.now().toString().slice(-6)}`,
      timestamp: new Date().toLocaleString(),
      type: "phishing",
      inputExcerpt: headerText.substring(0, 60) + "...",
      inputText: headerText,
      reports: [],
      phishingReport: null,
      maliciousCount: 0,
      warningsCount: 0
    };
    const updatedHistory = [newIncident, ...incidentHistory].slice(0, 100);
    setIncidentHistory(updatedHistory);
    localStorage.setItem("aegisflow_history", JSON.stringify(updatedHistory));
    addActivityLog(`Saved phishing header draft ${newIncident.id} in history log.`, "success");
    triggerSuccessModal("Email Draft Saved", `SMTP email headers have been logged to dashboard history as ${newIncident.id}.`);
  };

  // Load history item back to active workspaces
  const loadHistoryItem = (item: IncidentHistoryItem) => {
    addActivityLog(`Restored investigation state for ${item.id}.`, "info");
    if (item.type === "triage") {
      setInputText(item.inputText);
      setThreatReports(item.reports);
      if (item.reports.length > 0) {
        setSelectedReport(item.reports[0]);
      }
      setPhishingReport(null);
      setCurrentSection("triage");
    } else {
      setHeaderText(item.inputText);
      setPhishingReport(item.phishingReport);
      setThreatReports([]);
      setCurrentSection("phishing");
    }
  };

  const loadSampleData = (type: "logs" | "headers") => {
    addActivityLog(`Loaded demo payload data for ${type} audit.`, "info");
    if (type === "logs") {
      setInputText(SAMPLE_LOG);
      setCurrentSection("triage");
    } else {
      setHeaderText(SAMPLE_EMAIL);
      setCurrentSection("phishing");
    }
  };

  // Active scan statistics summaries (includes active log triage and active phishing audit)
  const activeMalCount = threatReports.filter(r => r.status === "malicious").length + (phishingReport && phishingReport.verdict === "malicious" ? 1 : 0);
  const activeSuspCount = threatReports.filter(r => r.status === "suspicious").length + (phishingReport && phishingReport.verdict === "suspicious" ? 1 : 0);
  const activeSafeCount = threatReports.filter(r => r.status === "safe").length + (phishingReport && phishingReport.verdict === "safe" ? 1 : 0);

  // Cumulative totals across the entire incident history log database
  const totalMalicious = incidentHistory.reduce((acc, item) => acc + item.maliciousCount, 0);
  const totalWarnings = incidentHistory.reduce((acc, item) => acc + item.warningsCount, 0);
  const totalIndicators = incidentHistory.reduce((acc, item) => acc + (item.type === "triage" ? item.reports.length : 1), 0);
  const totalThreatRatio = totalIndicators > 0 ? Math.round((totalMalicious / totalIndicators) * 100) : 0;

  // Render nodes for Threat Graph SVG
  const generateGraphData = () => {
    const nodes: Array<{ id: string; label: string; type: "ip" | "domain" | "hash" | "url"; status: string; x: number; y: number }> = [];
    const links: Array<{ source: string; target: string }> = [];

    const centerX = 350;
    const centerY = 200;

    threatReports.forEach((report, index) => {
      const angle = (index / threatReports.length) * 2 * Math.PI;
      const radius = 135;
      const x = centerX + radius * Math.cos(angle);
      const y = centerY + radius * Math.sin(angle);

      nodes.push({
        id: report.indicator,
        label: report.indicator.length > 20 ? report.indicator.substring(0, 17) + "..." : report.indicator,
        type: report.type,
        status: report.status,
        x,
        y
      });

      links.push({
        source: "INCIDENT-ALERT",
        target: report.indicator
      });
    });

    const cleanIP = "198.51.100.45";
    const maliciousHash = "275a021bcfb648915565ed19c297908b1fe69466544e999c15e8a56d8174120a";
    const maliciousDomain = "paypal-security-update.support";
    const maliciousURL = "http://banking-auth-secure.net/login.php";

    if (threatReports.some(r => r.indicator === cleanIP) && threatReports.some(r => r.indicator === maliciousHash)) {
      links.push({ source: maliciousHash, target: cleanIP });
    }
    if (threatReports.some(r => r.indicator === maliciousDomain) && threatReports.some(r => r.indicator === cleanIP)) {
      links.push({ source: maliciousDomain, target: cleanIP });
    }
    if (threatReports.some(r => r.indicator === maliciousURL) && threatReports.some(r => r.indicator === cleanIP)) {
      links.push({ source: maliciousURL, target: cleanIP });
    }

    return { nodes, links, centerX, centerY };
  };

  const graph = generateGraphData();

  // Export playbook helper
  const handleExportPlaybook = () => {
    const content = `AEGISFLOW INCIDENT REPORT & PLAYBOOK
Timestamp: ${new Date().toISOString()}
Indicators analyzed: ${threatReports.length}
Malicious: ${activeMalCount} | Suspicious: ${activeSuspCount} | Safe: ${activeSafeCount}

DETAILED IOC REPORT:
${threatReports.map(r => `- ${r.indicator} [${r.type.toUpperCase()}] status: ${r.status.toUpperCase()} (Score: ${r.score}%)
  Details: ${r.details}`).join("\n")}

CONTAINMENT ACTION COMMANDS:
Palo Alto Block CLI:
${threatReports.filter(r => r.status === "malicious" && r.type === "ip").map(r => `set shared address Aegis-Block-${r.indicator} ip-netmask ${r.indicator}`).join("\n")}

Fortinet CLI Block:
${threatReports.filter(r => r.status === "malicious" && r.type === "ip").map(r => `config firewall address\n  edit Aegis-Block-${r.indicator}\n  set subnet ${r.indicator} 255.255.255.255\n  end`).join("\n")}

Suricata NIDS Rules:
${threatReports.filter(r => r.status === "malicious" && r.type === "ip").map(r => `drop ip ${r.indicator} any -> any any (msg:"AegisFlow malicious IP Blocked"; sid:1000001; rev:1;)`).join("\n")}
`;
    
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "AegisFlow-Security-Playbook.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIndicator(id);
    setTimeout(() => setCopiedIndicator(null), 2000);
  };

  return (
    <div className="min-h-screen xl:h-screen xl:overflow-hidden bg-[#020408] bg-grid scanlines text-foreground flex flex-col xl:flex-row font-sans select-none relative">
      
      {/* SIDEBAR NAVIGATION PANEL */}
      <aside className="w-full xl:w-64 xl:fixed xl:left-0 xl:top-0 xl:bottom-0 xl:h-screen bg-[#090e1a]/95 border-b xl:border-b-0 xl:border-r border-border flex flex-col shrink-0 z-40 backdrop-blur-md">
        {/* Brand Header */}
        <div className="px-6 py-5 border-b border-border flex items-center gap-3">
          <Terminal className="text-primary size-6 glow-green animate-pulse" />
          <div>
            <h1 className="text-lg font-bold font-mono tracking-wider glow-green text-primary m-0 flex items-center gap-1.5">
              AEGISFLOW
            </h1>
            <p className="text-[10px] text-muted-foreground font-mono">CORTEX COMMAND CENTER</p>
          </div>
        </div>

        {/* Navigation Options */}
        <nav className="flex-grow p-4 flex flex-col gap-1.5">
          <button 
            onClick={() => setCurrentSection("overview")}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-md text-xs font-mono tracking-wide transition-all ${
              currentSection === "overview" 
                ? "bg-primary/10 text-primary border border-primary/20 glow-green" 
                : "text-muted-foreground hover:text-white hover:bg-slate-900/50 border border-transparent"
            }`}
          >
            <Home className="size-4" /> DASHBOARD OVERVIEW
          </button>

          <button 
            onClick={() => setCurrentSection("triage")}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-md text-xs font-mono tracking-wide transition-all ${
              currentSection === "triage" 
                ? "bg-primary/10 text-primary border border-primary/20 glow-green" 
                : "text-muted-foreground hover:text-white hover:bg-slate-900/50 border border-transparent"
            }`}
          >
            <Terminal className="size-4" /> IOC LOG TRIAGE
          </button>

          <button 
            onClick={() => setCurrentSection("phishing")}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-md text-xs font-mono tracking-wide transition-all ${
              currentSection === "phishing" 
                ? "bg-primary/10 text-primary border border-primary/20 glow-green" 
                : "text-muted-foreground hover:text-white hover:bg-slate-900/50 border border-transparent"
            }`}
          >
            <Mail className="size-4" /> PHISHING ROUTING
          </button>

          <button 
            onClick={() => setCurrentSection("graph")}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-md text-xs font-mono tracking-wide transition-all ${
              currentSection === "graph" 
                ? "bg-primary/10 text-primary border border-primary/20 glow-green" 
                : "text-muted-foreground hover:text-white hover:bg-slate-900/50 border border-transparent"
            }`}
          >
            <Share2 className="size-4" /> THREAT CANVAS
          </button>

          <button 
            onClick={() => setCurrentSection("playbook")}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-md text-xs font-mono tracking-wide transition-all ${
              currentSection === "playbook" 
                ? "bg-primary/10 text-primary border border-primary/20 glow-green" 
                : "text-muted-foreground hover:text-white hover:bg-slate-900/50 border border-transparent"
            }`}
          >
            <FileText className="size-4" /> AI PLAYBOOKS
          </button>

          <div className="border-t border-border/60 my-3" />

          <button 
            onClick={() => setSettingsOpen(true)}
            className="w-full flex items-center gap-3 px-4 py-3 rounded-md text-xs font-mono tracking-wide text-muted-foreground hover:text-white hover:bg-slate-900/50 transition-all border border-transparent"
          >
            <Settings className="size-4" /> CONFIGURE API KEYS
          </button>
        </nav>

        {/* System telemetry health status footer */}
        <div className="p-4 border-t border-border bg-[#05070e]/80">
          <div className="flex flex-col gap-2 font-mono text-[9px]">
            <div className="flex justify-between items-center">
              <span className="text-muted-foreground">ABUSEIPDB:</span>
              <span className={apiKeys.abuseIPDB ? "text-primary flex items-center gap-1 glow-green" : "text-amber-500 flex items-center gap-1"}>
                <Activity className="size-2 animate-pulse" /> {apiKeys.abuseIPDB ? "LIVE" : "NOT SET"}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-muted-foreground">VIRUSTOTAL:</span>
              <span className={apiKeys.virusTotal ? "text-primary flex items-center gap-1 glow-green" : "text-amber-500 flex items-center gap-1"}>
                <Activity className="size-2 animate-pulse" /> {apiKeys.virusTotal ? "LIVE" : "NOT SET"}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-muted-foreground">ALIENVAULT OTX:</span>
              <span className={apiKeys.alienVaultOTX ? "text-primary flex items-center gap-1 glow-green" : "text-amber-500 flex items-center gap-1"}>
                <Activity className="size-2" /> {apiKeys.alienVaultOTX ? "LIVE" : "NOT SET"}
              </span>
            </div>
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT AREA */}
      <div className="flex-grow flex flex-col min-w-0 xl:pl-64 xl:h-screen xl:overflow-hidden">
        
        {/* TOP STATUS BAR */}
        <header className="border-b border-border bg-[#090e1a]/85 backdrop-blur-md px-6 py-4 flex justify-between items-center shadow-md z-30">
          <div className="flex items-center gap-3">
            <Badge variant="outline" className="border-primary/20 bg-primary/5 text-primary text-[10px] uppercase font-mono px-2 py-0.5 tracking-wider">
              {currentSection === "overview" ? "SYSTEM RUNTIME OVERVIEW" : `${currentSection.toUpperCase()} WORKSPACE`}
            </Badge>
            {isSimulatedMode && (
              <Badge className="bg-amber-500/10 border border-amber-500/30 text-amber-500 text-[9px] font-mono tracking-wide px-2 py-0.5">
                SIMULATION MODE (NO API KEYS)
              </Badge>
            )}
          </div>

          <div className="flex items-center gap-4 text-xs font-mono">
            <span className="text-destructive flex items-center gap-1 bg-destructive/10 px-2.5 py-1 rounded border border-destructive/20" title="Active workspace malicious detections">
              <ShieldAlert className="size-3.5" /> {activeMalCount} Active Malicious
            </span>
            <span className="text-amber-500 flex items-center gap-1 bg-amber-500/10 px-2.5 py-1 rounded border border-amber-500/20" title="Active workspace warnings">
              <AlertTriangle className="size-3.5 animate-pulse" /> {activeSuspCount} Active Warnings
            </span>
          </div>

          {/* Configuration Dialog Wrapper */}
          <Dialog open={settingsOpen} onOpenChange={setSettingsOpen}>
            <DialogContent className="bg-card text-foreground border-border max-w-md">
              <DialogHeader>
                <DialogTitle className="font-mono text-primary glow-green">Threat Intel API Keys</DialogTitle>
                <DialogDescription className="text-xs text-muted-foreground">
                  Provide your API keys to query live Threat Intelligence endpoints. Keys are stored locally in your browser.
                </DialogDescription>
              </DialogHeader>
              <SettingsForm keys={apiKeys} onSave={saveKeys} onClose={() => setSettingsOpen(false)} />
            </DialogContent>
          </Dialog>

          {/* API Key Missing Warning Dialog */}
          <Dialog open={showKeyWarning} onOpenChange={setShowKeyWarning}>
            <DialogContent className="bg-card text-foreground border-border max-w-md">
              <DialogHeader>
                <DialogTitle className="font-mono text-amber-500 flex items-center gap-2">
                  <AlertTriangle className="size-5 text-amber-500 animate-pulse" /> 
                  API KEYS REQUIRED
                </DialogTitle>
                <DialogDescription className="text-xs text-slate-300 leading-relaxed pt-2">
                  AegisFlow is running in simulated sandbox mode. To query live threat database scores from **VirusTotal**, **AbuseIPDB**, and **AlienVault OTX**, you must configure your API keys first.
                </DialogDescription>
              </DialogHeader>
              <div className="flex flex-col gap-4 pt-3">
                <p className="text-[11px] text-muted-foreground leading-relaxed font-mono">
                  Sandbox mode uses mock response indicators for demonstration. Configure your profile with your actual API keys to enable fully functional production lookups.
                </p>
                <div className="flex gap-2 justify-end font-mono text-xs">
                  <Button 
                    variant="outline" 
                    onClick={() => {
                      setShowKeyWarning(false);
                      if (warningCallback) warningCallback.action();
                    }}
                    className="border-border hover:bg-secondary text-xs"
                  >
                    CONTINUE IN SANDBOX
                  </Button>
                  <Button 
                    onClick={() => {
                      setShowKeyWarning(false);
                      setSettingsOpen(true);
                    }} 
                    className="bg-primary text-background hover:bg-primary/80 text-xs font-bold"
                  >
                    CONFIGURE API KEYS
                  </Button>
                </div>
              </div>
            </DialogContent>
          </Dialog>

          {/* Global Success Notification Dialog */}
          <Dialog open={successModalOpen} onOpenChange={setSuccessModalOpen}>
            <DialogContent className="bg-card text-foreground border-primary/20 max-w-xs border-glow-green text-center">
              <DialogHeader className="flex flex-col items-center gap-2">
                <div className="size-12 rounded-full bg-primary/10 border border-primary/30 flex items-center justify-center glow-green mb-1">
                  <Check className="size-6 text-primary glow-green" />
                </div>
                <DialogTitle className="font-mono text-primary uppercase text-[13px] tracking-wider glow-green">
                  {successModalContent.title}
                </DialogTitle>
                <DialogDescription className="text-xs text-slate-300 leading-relaxed font-sans pt-1">
                  {successModalContent.message}
                </DialogDescription>
              </DialogHeader>
              <div className="flex justify-center pt-2 font-mono">
                <Button 
                  onClick={() => setSuccessModalOpen(false)}
                  className="bg-primary hover:bg-primary/80 text-background text-xs px-6 py-1.5 font-bold tracking-wider"
                >
                  CONFIRM
                </Button>
              </div>
            </DialogContent>
          </Dialog>

          {/* Analysis Loading State Dialog */}
          <Dialog open={analysisLoadingOpen} onOpenChange={() => {}}>
            <DialogContent className="bg-card text-foreground border-primary/20 max-w-xs border-glow-green text-center">
              <DialogHeader className="flex flex-col items-center gap-3">
                <RefreshCw className="size-8 animate-spin text-primary glow-green mb-1" />
                <DialogTitle className="font-mono text-primary uppercase text-xs tracking-wider glow-green animate-pulse">
                  SYSTEM ANALYZING
                </DialogTitle>
                <DialogDescription className="text-[10px] text-slate-300 font-mono leading-relaxed pt-1">
                  {analysisLoadingMessage}
                </DialogDescription>
              </DialogHeader>
            </DialogContent>
          </Dialog>

          {/* Delete Single Item Confirmation Dialog */}
          <Dialog open={deleteConfirmationOpen} onOpenChange={setDeleteConfirmationOpen}>
            <DialogContent className="bg-card text-foreground border-destructive/20 max-w-xs text-center border-glow-red">
              <DialogHeader className="flex flex-col items-center gap-2">
                <div className="size-12 rounded-full bg-destructive/10 border border-destructive/30 flex items-center justify-center glow-red mb-1">
                  <AlertTriangle className="size-6 text-destructive glow-red" />
                </div>
                <DialogTitle className="font-mono text-destructive uppercase text-xs tracking-wider glow-red">
                  DELETE RECORD?
                </DialogTitle>
                <DialogDescription className="text-[11px] text-slate-300 leading-relaxed font-sans pt-1">
                  Are you sure you want to permanently delete investigation record <span className="text-destructive font-mono font-bold">{itemToDelete}</span>? This action cannot be undone.
                </DialogDescription>
              </DialogHeader>
              <div className="flex gap-2 justify-center pt-3 font-mono text-[10px]">
                <Button 
                  variant="outline"
                  onClick={() => {
                    setDeleteConfirmationOpen(false);
                    setItemToDelete(null);
                  }}
                  className="border-border hover:bg-secondary text-[10px] px-3.5 h-7"
                >
                  CANCEL
                </Button>
                <Button 
                  onClick={() => {
                    if (itemToDelete) {
                      confirmDeleteHistoryItem(itemToDelete);
                    }
                  }}
                  className="bg-destructive hover:bg-destructive/80 text-white text-[10px] px-3.5 h-7 font-bold"
                >
                  DELETE RECORD
                </Button>
              </div>
            </DialogContent>
          </Dialog>

          {/* Clear All History Confirmation Dialog */}
          <Dialog open={clearConfirmationOpen} onOpenChange={setClearConfirmationOpen}>
            <DialogContent className="bg-card text-foreground border-destructive/20 max-w-xs text-center border-glow-red">
              <DialogHeader className="flex flex-col items-center gap-2">
                <div className="size-12 rounded-full bg-destructive/10 border border-destructive/30 flex items-center justify-center glow-red mb-1">
                  <AlertTriangle className="size-6 text-destructive glow-red" />
                </div>
                <DialogTitle className="font-mono text-destructive uppercase text-xs tracking-wider glow-red">
                  CLEAR ALL HISTORY?
                </DialogTitle>
                <DialogDescription className="text-[11px] text-slate-300 leading-relaxed font-sans pt-1">
                  Are you sure you want to delete your entire triage and email investigation history? All session logs and drafts will be lost.
                </DialogDescription>
              </DialogHeader>
              <div className="flex gap-2 justify-center pt-3 font-mono text-[10px]">
                <Button 
                  variant="outline"
                  onClick={() => setClearConfirmationOpen(false)}
                  className="border-border hover:bg-secondary text-[10px] px-3.5 h-7"
                >
                  CANCEL
                </Button>
                <Button 
                  onClick={() => {
                    confirmClearHistory();
                  }}
                  className="bg-destructive hover:bg-destructive/80 text-white text-[10px] px-3.5 h-7 font-bold"
                >
                  CLEAR ALL
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </header>

        {/* WORKSPACE CONTENT BODY */}
        <main className="p-6 flex-grow overflow-y-auto max-w-7xl w-full mx-auto">
          
          {/* SECTION 1: SYSTEM OVERVIEW */}
          {currentSection === "overview" && (
            <div className="flex flex-col gap-6 animate-fade-in">
              {/* Warnings Banners if keys are not set */}
              {isSimulatedMode && (
                <div className="bg-amber-500/5 border border-amber-500/20 rounded-md p-4 text-xs font-mono flex items-start gap-3">
                  <AlertTriangle className="size-4.5 text-amber-500 shrink-0 mt-0.5" />
                  <div>
                    <span className="text-amber-500 font-bold block">API KEYS NOT CONFIGURED</span>
                    <p className="text-slate-400 mt-1 leading-relaxed">
                      AegisFlow is running in simulated sandbox mode. Detections will run local test simulations. Paste actual keys in the **Configure API Keys** sidebar panel to fetch live VirusTotal, AbuseIPDB, and AlienVault threat scores.
                    </p>
                  </div>
                </div>
              )}

              {/* Welcome & Stats grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                
                {/* Stats Malicious */}
                <Card className="border-destructive/30 bg-destructive/5 backdrop-blur-sm shadow-lg border-glow-red relative overflow-hidden">
                  <CardHeader className="pb-2">
                    <CardTitle className="font-mono text-xs text-destructive tracking-widest uppercase">CRITICAL DETECTIONS</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-3xl font-mono font-bold text-destructive glow-red">{totalMalicious}</div>
                    <p className="text-xs text-slate-400 mt-2">Total malicious indicators detected across all session logs.</p>
                  </CardContent>
                </Card>

                {/* Stats Warnings */}
                <Card className="border-amber-500/30 bg-amber-500/5 backdrop-blur-sm shadow-lg relative overflow-hidden">
                  <CardHeader className="pb-2">
                    <CardTitle className="font-mono text-xs text-amber-500 tracking-widest uppercase">SUSPICIOUS WARNINGS</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-3xl font-mono font-bold text-amber-500">{totalWarnings}</div>
                    <p className="text-xs text-slate-400 mt-2">Total warning indicators detected in this session's database.</p>
                  </CardContent>
                </Card>

                {/* Threat Index Score */}
                <Card className="border-primary/30 bg-primary/5 backdrop-blur-sm shadow-lg border-glow-green relative overflow-hidden">
                  <CardHeader className="pb-2">
                    <CardTitle className="font-mono text-xs text-primary tracking-widest uppercase">THREAT INDEX RATIO</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-3xl font-mono font-bold text-primary glow-green">
                      {totalThreatRatio}%
                    </div>
                    <p className="text-xs text-slate-400 mt-2">Calculated priority weight of all triaged indicators.</p>
                  </CardContent>
                </Card>

              </div>

              {/* Ingest Quick Test Playgrounds */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                
                {/* Log Triage demo box */}
                <Card className="border-border bg-card/65 backdrop-blur-sm shadow-xl relative overflow-hidden">
                  <div className="absolute top-0 left-0 right-0 h-[1.5px] bg-primary/50" />
                  <CardHeader>
                    <CardTitle className="font-mono text-sm text-primary flex justify-between items-center">
                      <span>1. LOG TRIAGE RUNNER</span>
                      <Terminal className="size-4 text-primary" />
                    </CardTitle>
                    <CardDescription className="text-xs">
                      Analyze logs and extract threat indicators.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="text-xs font-mono text-slate-300">
                    <p className="mb-4 leading-relaxed bg-background/50 p-3 rounded border border-border">
                      Extracts URLs, domain names, hashes, and IPs from raw log buffers. Resolves reputations across APIs.
                    </p>
                    <div className="flex gap-2">
                      <Button 
                        onClick={() => loadSampleData("logs")}
                        className="w-full bg-primary hover:bg-primary/80 text-background font-mono text-xs"
                      >
                        LOAD LOG TRIAGE PLAYGROUND
                      </Button>
                    </div>
                  </CardContent>
                </Card>

                {/* Phishing Ingest demo box */}
                <Card className="border-border bg-card/65 backdrop-blur-sm shadow-xl relative overflow-hidden">
                  <div className="absolute top-0 left-0 right-0 h-[1.5px] bg-accent/50" />
                  <CardHeader>
                    <CardTitle className="font-mono text-sm text-accent flex justify-between items-center">
                      <span>2. PHISHING ROUTING AUDITOR</span>
                      <Mail className="size-4 text-accent" />
                    </CardTitle>
                    <CardDescription className="text-xs">
                      Audit SMTP server received lines and alignment keys.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="text-xs font-mono text-slate-300">
                    <p className="mb-4 leading-relaxed bg-background/50 p-3 rounded border border-border">
                      Extracts SPF, DKIM, DMARC key records from email headers. Visualizes relay hop routing paths.
                    </p>
                    <div className="flex gap-2">
                      <Button 
                        onClick={() => loadSampleData("headers")}
                        className="w-full bg-accent hover:bg-accent/80 text-background font-mono text-xs"
                      >
                        LOAD PHISHING AUDIT PLAYGROUND
                      </Button>
                    </div>
                  </CardContent>
                </Card>

              </div>

              {/* TWO COLUMN ROW: INVESTIGATION HISTORY & SYSTEM ACTIVITY LOG */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                {/* RECENT INVESTIGATIONS HISTORY */}
                <Card className="border-border bg-card/65 backdrop-blur-sm shadow-xl flex flex-col lg:col-span-7">
                  <CardHeader className="pb-3 border-b border-border bg-background/25 flex flex-row justify-between items-center">
                    <div>
                      <CardTitle className="font-mono text-xs text-primary flex items-center gap-2">
                        <Clock className="size-4 text-primary" /> SESSION INVESTIGATION HISTORY ({incidentHistory.length})
                      </CardTitle>
                      <CardDescription className="text-xs">
                        History of triaged logs and phishing header audits in this session.
                      </CardDescription>
                    </div>
                    {incidentHistory.length > 0 && (
                      <Button 
                        variant="ghost" 
                        onClick={clearHistory}
                        className="h-7 px-2 text-[10px] font-mono text-destructive hover:bg-destructive/10 flex gap-1 items-center"
                      >
                        <Trash2 className="size-3" /> CLEAR HISTORY
                      </Button>
                    )}
                  </CardHeader>
                  <CardContent className="p-0 overflow-y-auto max-h-[300px]">
                    {incidentHistory.length === 0 ? (
                      <div className="p-8 text-center text-muted-foreground font-mono text-xs flex flex-col items-center justify-center h-48">
                        No investigations recorded. Run Triage or Header Audits to build logs.
                      </div>
                    ) : (
                      <Table>
                        <TableHeader className="bg-background/80 sticky top-0">
                          <TableRow className="border-border">
                            <TableHead className="font-mono text-xs w-[120px]">TIMESTAMP</TableHead>
                            <TableHead className="font-mono text-xs w-[80px]">TYPE</TableHead>
                            <TableHead className="font-mono text-xs">EXCERPT</TableHead>
                            <TableHead className="font-mono text-xs w-[120px] text-right">DETECTIONS</TableHead>
                            <TableHead className="w-[50px]"></TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {incidentHistory.map((item) => (
                            <TableRow 
                              key={item.id} 
                              onClick={() => loadHistoryItem(item)}
                              className="cursor-pointer border-border hover:bg-background/45 transition-colors"
                            >
                              <TableCell className="font-mono text-xs text-slate-400">
                                {item.timestamp}
                              </TableCell>
                              <TableCell>
                                <Badge variant="outline" className={`text-[8px] uppercase font-mono px-1.5 py-0.5 ${
                                  item.type === "triage" ? "border-primary/30 text-primary bg-primary/5" : "border-accent/30 text-accent bg-accent/5"
                                }`}>
                                  {item.type}
                                </Badge>
                              </TableCell>
                              <TableCell className="font-mono text-xs text-slate-300 truncate max-w-[180px] sm:max-w-[280px]" title={item.inputText}>
                                {item.inputExcerpt}
                              </TableCell>
                              <TableCell className="text-right">
                                <span className={`font-mono text-xs font-semibold ${
                                  item.maliciousCount > 0 ? "text-destructive glow-red" : 
                                  item.warningsCount > 0 ? "text-amber-500" : "text-emerald-500"
                                }`}>
                                  {item.maliciousCount} Malicious / {item.warningsCount} Warn
                                </span>
                              </TableCell>
                              <TableCell className="text-right">
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    deleteHistoryItem(item.id);
                                  }}
                                  className="h-7 w-7 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                                  title="Delete this entry"
                                >
                                  <Trash2 className="size-3.5" />
                                </Button>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    )}
                  </CardContent>
                </Card>

                {/* SYSTEM ACTIVITY CONSOLE */}
                <Card className="border-border bg-card/65 backdrop-blur-sm shadow-xl flex flex-col lg:col-span-5">
                  <CardHeader className="pb-3 border-b border-border bg-background/25 flex flex-row justify-between items-center">
                    <div>
                      <CardTitle className="font-mono text-xs text-primary flex items-center gap-2">
                        <Terminal className="size-4 text-primary glow-green animate-pulse" /> CORTEX ACTIVITY CONSOLE
                      </CardTitle>
                      <CardDescription className="text-xs">
                        Real-time audit log of active session operations.
                      </CardDescription>
                    </div>
                    {activityLogs.length > 0 && (
                      <Button 
                        variant="ghost" 
                        onClick={() => {
                          setActivityLogs([]);
                          localStorage.removeItem("aegisflow_activity_logs");
                        }}
                        className="h-7 px-2 text-[10px] font-mono text-destructive hover:bg-destructive/10 flex gap-1 items-center"
                      >
                        <Trash2 className="size-3" /> CLEAR LOGS
                      </Button>
                    )}
                  </CardHeader>
                  <CardContent className="p-4 overflow-y-auto max-h-[300px] font-mono text-[10px] flex flex-col gap-1.5 scrollbar-thin">
                    {activityLogs.length === 0 ? (
                      <div className="p-8 text-center text-muted-foreground font-mono text-xs flex flex-col items-center justify-center h-48">
                        No activity recorded. Run triage audits to generate entries.
                      </div>
                    ) : (
                      activityLogs.map((log, index) => {
                        const typeColors = {
                          info: "text-blue-400",
                          warning: "text-amber-500",
                          success: "text-primary glow-green",
                          danger: "text-destructive glow-red"
                        };
                        return (
                          <div key={index} className="flex gap-2 items-start hover:bg-background/20 py-0.5 px-1 rounded transition-colors select-text">
                            <span className="text-muted-foreground shrink-0">[{log.timestamp}]</span>
                            <span className={`${typeColors[log.type] || "text-foreground"} break-all`}>
                              {log.type === "danger" ? "🚨 " : log.type === "warning" ? "⚠️ " : "» "} 
                              {log.message}
                            </span>
                          </div>
                        );
                      })
                    )}
                  </CardContent>
                </Card>

              </div>

            </div>
          )}

          {/* SECTION 2: LOG TRIAGE */}
          {currentSection === "triage" && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 animate-fade-in">
              {/* Input Area (5 columns) */}
              <div className="lg:col-span-5 flex flex-col">
                <Card className="border-border bg-card/65 backdrop-blur-sm flex flex-col h-full shadow-2xl">
                  <CardHeader className="pb-4">
                    <CardTitle className="font-mono text-xs tracking-wider text-primary flex justify-between items-center">
                      <span>LOG BRIEF INPUT</span>
                      <Terminal className="size-4" />
                    </CardTitle>
                    <CardDescription className="text-xs">Paste logs, alert messages, or hashes below.</CardDescription>
                  </CardHeader>
                  <CardContent className="flex flex-col gap-4 flex-grow">
                    <Textarea 
                      value={inputText}
                      onChange={(e) => setInputText(e.target.value)}
                      placeholder="Paste firewall alerts, hashes, IPs, or logs..."
                      className="min-h-[360px] bg-background border-border text-xs font-mono focus-visible:ring-primary focus-visible:ring-1 leading-relaxed"
                    />
                    <div className="flex gap-2">
                      <Button 
                        onClick={handleTriage} 
                        disabled={isProcessing}
                        className="flex-grow bg-primary hover:bg-primary/80 text-background font-mono text-xs tracking-wider"
                      >
                        {isProcessing ? (
                          <>
                            <RefreshCw className="size-3.5 animate-spin mr-2" /> ENRICHING IOCS...
                          </>
                        ) : (
                          <>
                            <Play className="size-3.5 mr-2" /> EXTRACT & ENRICH
                          </>
                        )}
                      </Button>
                      <Button 
                        variant="outline"
                        onClick={handleSaveTriageDraft}
                        disabled={!inputText.trim() || isProcessing}
                        className="border-primary/30 text-primary hover:bg-primary/10 font-mono text-xs px-3"
                        title="Save log to dashboard history as draft"
                      >
                        SAVE DRAFT
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Output & Inspector (7 columns) */}
              <div className="lg:col-span-7 flex flex-col gap-6">
                <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
                  
                  {/* Extracted table */}
                  <Card className="border-border bg-card/65 backdrop-blur-sm shadow-xl md:col-span-6 flex flex-col min-h-[460px]">
                    <CardHeader className="pb-2">
                      <CardTitle className="font-mono text-xs tracking-wider text-primary">EXTRACTED INDICATORS</CardTitle>
                    </CardHeader>
                    <CardContent className="p-0 overflow-y-auto flex-grow">
                      {isProcessing ? (
                        /* Shimmer Loading State */
                        <div className="p-4 flex flex-col gap-4">
                          <div className="h-7 bg-slate-900/80 animate-pulse rounded border border-border/20" />
                          <div className="h-7 bg-slate-900/80 animate-pulse rounded border border-border/20 w-11/12" />
                          <div className="h-7 bg-slate-900/80 animate-pulse rounded border border-border/20 w-4/5" />
                          <div className="h-7 bg-slate-900/80 animate-pulse rounded border border-border/20 w-3/4" />
                        </div>
                      ) : threatReports.length === 0 ? (
                        <div className="p-8 text-center text-muted-foreground font-mono text-xs flex flex-col items-center justify-center h-48">
                          <Info className="size-6 text-muted/30 mb-2" />
                          No active threat reports. Run triage to parse data.
                        </div>
                      ) : (
                        <Table>
                          <TableHeader className="bg-background/80 sticky top-0">
                            <TableRow className="border-border">
                              <TableHead className="font-mono text-xs">INDICATOR</TableHead>
                              <TableHead className="font-mono text-xs">STATUS</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {threatReports.map((report) => (
                              <TableRow 
                                key={report.indicator} 
                                onClick={() => setSelectedReport(report)}
                                className={`cursor-pointer border-border transition-colors ${selectedReport?.indicator === report.indicator ? 'bg-primary/5' : 'hover:bg-background/45'}`}
                              >
                                <TableCell className="font-mono text-xs truncate max-w-[130px]" title={report.indicator}>
                                  {report.indicator}
                                </TableCell>
                                <TableCell className="text-right">
                                  <span className={`font-mono text-[10px] font-semibold ${
                                    report.status === "malicious" ? "text-destructive glow-red" : 
                                    report.status === "suspicious" ? "text-amber-500" : "text-emerald-500 animate-pulse"
                                  }`}>
                                    {report.score}% {report.status.toUpperCase()}
                                  </span>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      )}
                    </CardContent>
                  </Card>

                  {/* Telemetry Inspector */}
                  <Card className="border-border bg-card/65 backdrop-blur-sm shadow-xl md:col-span-6 flex flex-col min-h-[460px]">
                    <CardHeader className="pb-2 border-b border-border bg-background/35">
                      <div className="flex justify-between items-start">
                        <CardTitle className="font-mono text-xs text-primary">TELEMETRY DETAIL</CardTitle>
                        {selectedReport && !isProcessing && (
                          <Badge className={`${
                            selectedReport.status === "malicious" ? "bg-destructive text-white" :
                            selectedReport.status === "suspicious" ? "bg-amber-500 text-slate-950" : "bg-emerald-500 text-slate-950"
                          } text-[9px] font-mono`}>
                            {selectedReport.status.toUpperCase()}
                          </Badge>
                        )}
                      </div>
                    </CardHeader>
                    <CardContent className="pt-4 flex-grow overflow-y-auto flex flex-col gap-4 font-mono text-xs">
                      {isProcessing ? (
                        /* Spinner Loading State */
                        <div className="p-6 flex flex-col items-center justify-center h-48 gap-3">
                          <RefreshCw className="size-8 animate-spin text-primary glow-green" />
                          <span className="font-mono text-[10px] text-primary animate-pulse">TRIAGING TELEMETRY...</span>
                        </div>
                      ) : selectedReport ? (
                        <div className="flex flex-col gap-4">
                          <div>
                            <div className="flex justify-between items-center">
                              <span className="text-muted-foreground block text-[9px]">TARGET:</span>
                              <Button 
                                variant="ghost" 
                                onClick={() => copyToClipboard(selectedReport.indicator, selectedReport.indicator)} 
                                className="h-5 px-1.5 text-[9px] hover:bg-slate-900 border border-slate-900"
                              >
                                {copiedIndicator === selectedReport.indicator ? (
                                  <Check className="size-3 text-primary mr-1" />
                                ) : (
                                  <Copy className="size-3 mr-1" />
                                )}
                                {copiedIndicator === selectedReport.indicator ? "COPIED" : "COPY"}
                              </Button>
                            </div>
                            <span className="text-foreground font-semibold break-all text-xs">{selectedReport.indicator}</span>
                          </div>
                          
                          <div>
                            <span className="text-muted-foreground block text-[9px]">ANALYSIS SUMMARY:</span>
                            <p className="text-slate-300 text-xs mt-1 leading-relaxed bg-background/50 p-2.5 rounded border border-border">
                              {selectedReport.details}
                            </p>
                          </div>

                          <div className="grid grid-cols-2 gap-2 mt-1">
                            <div className="bg-background/40 p-2.5 rounded border border-border">
                              <span className="text-muted-foreground block text-[9px]">VIRUSTOTAL</span>
                              <span className="text-foreground text-sm font-semibold block mt-1">
                                {selectedReport.sources.virusTotal?.score || "0/0"}
                              </span>
                            </div>
                            {selectedReport.type === "ip" && (
                              <div className="bg-background/40 p-2.5 rounded border border-border">
                                <span className="text-muted-foreground block text-[9px]">ABUSEIPDB</span>
                                <span className="text-foreground text-sm font-semibold block mt-1">
                                  {selectedReport.sources.abuseIPDB?.reports || 0} hits
                                </span>
                              </div>
                            )}
                            <div className="bg-background/40 p-2.5 rounded border border-border col-span-2">
                              <span className="text-muted-foreground block text-[9px] mb-1">OTX PULSE TAGS</span>
                              <div className="flex flex-wrap gap-1 mt-1">
                                {selectedReport.sources.alienVaultOTX?.tags.map(tag => (
                                  <Badge key={tag} className="bg-slate-900 border border-primary/20 text-primary text-[8px] px-1 py-0.5 uppercase tracking-wider">
                                    {tag}
                                  </Badge>
                                )) || <span className="text-muted-foreground text-[9px]">No tags</span>}
                              </div>
                            </div>
                          </div>
                        </div>
                      ) : (
                        <div className="p-8 text-center text-muted-foreground font-mono text-xs flex flex-col items-center justify-center h-48">
                          <Info className="size-6 text-muted/30" />
                          Select indicator row.
                        </div>
                      )}
                    </CardContent>
                  </Card>

                </div>
              </div>
            </div>
          )}

          {/* SECTION 3: PHISHING EMAIL ROUTING PATH */}
          {currentSection === "phishing" && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 animate-fade-in">
              {/* Input Area (4 columns) */}
              <div className="lg:col-span-4 flex flex-col">
                <Card className="border-border bg-card/65 backdrop-blur-sm flex flex-col h-full shadow-2xl">
                  <CardHeader className="pb-4">
                    <CardTitle className="font-mono text-xs tracking-wider text-accent flex justify-between items-center">
                      <span>PHISHING HEADER INPUT</span>
                      <Mail className="size-4" />
                    </CardTitle>
                    <CardDescription className="text-xs">Paste raw email headers block below.</CardDescription>
                  </CardHeader>
                  <CardContent className="flex flex-col gap-4 flex-grow">
                    <Textarea 
                      value={headerText}
                      onChange={(e) => setHeaderText(e.target.value)}
                      placeholder="Paste raw email header source..."
                      className="min-h-[360px] bg-background border-border text-xs font-mono focus-visible:ring-accent focus-visible:ring-1 leading-relaxed"
                    />
                    <div className="flex gap-2">
                      <Button 
                        onClick={handleParseHeaders}
                        className="flex-grow bg-accent hover:bg-accent/80 text-background font-mono text-xs tracking-wider"
                      >
                        <Server className="size-3.5 mr-2" /> AUDIT SMTP ROUTE
                      </Button>
                      <Button 
                        variant="outline"
                        onClick={handleSavePhishingDraft}
                        disabled={!headerText.trim()}
                        className="border-accent/30 text-accent hover:bg-accent/10 font-mono text-xs px-3"
                        title="Save email headers to dashboard history as draft"
                      >
                        SAVE DRAFT
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Phishing Outputs (8 columns) */}
              <div className="lg:col-span-8 flex flex-col gap-6">
                {isProcessing ? (
                  <Card className="border-border bg-card/65 backdrop-blur-sm shadow-xl p-12 text-center text-muted-foreground font-mono text-xs flex flex-col items-center justify-center min-h-[300px]">
                    <RefreshCw className="size-8 animate-spin text-accent glow-cyan mb-3" />
                    <span className="font-mono text-[10px] text-accent animate-pulse">AUDITING HEADER PATHWAYS...</span>
                  </Card>
                ) : phishingReport ? (
                  <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
                    
                    {/* Alignment Detections */}
                    <Card className="border-border bg-card/65 backdrop-blur-sm shadow-xl md:col-span-5 flex flex-col">
                      <CardHeader className="pb-2">
                        <CardTitle className="font-mono text-xs tracking-wider text-accent">SMTP AUTHENTICATIONS</CardTitle>
                      </CardHeader>
                      <CardContent className="flex flex-col gap-3 font-mono text-xs">
                        <div className="flex justify-between items-center bg-background/50 p-2.5 rounded border border-border">
                          <div>
                            <span className="font-bold text-[10px]">SPF CHECK</span>
                            <span className="block text-[9px] text-muted-foreground">{phishingReport.spf.details}</span>
                          </div>
                          <Badge className={`${phishingReport.spf.status === "PASS" ? "bg-emerald-500 text-slate-950" : "bg-destructive text-white"} text-[9px] font-mono`}>
                            {phishingReport.spf.status}
                          </Badge>
                        </div>

                        <div className="flex justify-between items-center bg-background/50 p-2.5 rounded border border-border">
                          <div>
                            <span className="font-bold text-[10px]">DKIM SIGNATURE</span>
                            <span className="block text-[9px] text-muted-foreground">{phishingReport.dkim.details}</span>
                          </div>
                          <Badge className={`${phishingReport.dkim.status === "PASS" ? "bg-emerald-500 text-slate-950" : "bg-destructive text-white"} text-[9px] font-mono`}>
                            {phishingReport.dkim.status}
                          </Badge>
                        </div>

                        <div className="flex justify-between items-center bg-background/50 p-2.5 rounded border border-border">
                          <div>
                            <span className="font-bold text-[10px]">DMARC ALIGN</span>
                            <span className="block text-[9px] text-muted-foreground">{phishingReport.dmarc.details}</span>
                          </div>
                          <Badge className={`${phishingReport.dmarc.status === "PASS" ? "bg-emerald-500 text-slate-950" : "bg-destructive text-white"} text-[9px] font-mono`}>
                            {phishingReport.dmarc.status}
                          </Badge>
                        </div>

                        <div className="bg-background/25 border border-accent/20 p-3 rounded-md text-[10px] flex flex-col gap-1.5 mt-2">
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">SPF ALIGNMENT:</span>
                            <span className={phishingReport.alignment.spfAligned ? "text-primary glow-green font-bold" : "text-destructive glow-red font-bold"}>
                              {phishingReport.alignment.spfAligned ? "ALIGNED" : "MISALIGNED"}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">DKIM ALIGNMENT:</span>
                            <span className={phishingReport.alignment.dkimAligned ? "text-primary glow-green font-bold" : "text-destructive glow-red font-bold"}>
                              {phishingReport.alignment.dkimAligned ? "ALIGNED" : "MISALIGNED"}
                            </span>
                          </div>
                        </div>
                      </CardContent>
                    </Card>

                    {/* Routing Hops */}
                    <Card className="border-border bg-card/65 backdrop-blur-sm shadow-xl md:col-span-7 flex flex-col max-h-[460px]">
                      <CardHeader className="pb-3 border-b border-border bg-background/25 flex flex-row justify-between items-center">
                        <div>
                          <CardTitle className="font-mono text-xs text-accent">SMTP TRANSMISSION PATH</CardTitle>
                        </div>
                        <Badge className={`${
                          phishingReport.verdict === "malicious" ? "bg-destructive text-white" :
                          phishingReport.verdict === "suspicious" ? "bg-amber-500 text-slate-950" : "bg-emerald-500 text-slate-950"
                        } text-[9px] font-mono`}>
                          {phishingReport.verdict.toUpperCase()} VERDICT
                        </Badge>
                      </CardHeader>
                      <CardContent className="pt-4 flex-grow overflow-y-auto flex flex-col gap-4">
                        <div className="flex flex-col gap-3 relative pl-4 border-l border-border/80 ml-2">
                          {phishingReport.hops.map((hop) => (
                            <div key={hop.step} className="relative mb-2">
                              {/* dot */}
                              <div className={`absolute -left-[20.5px] top-1 size-3 rounded-full border-2 border-background ${
                                hop.suspicious ? "bg-destructive animate-ping" : "bg-primary"
                              }`} />
                              <div className={`absolute -left-[20.5px] top-1 size-3 rounded-full border-2 border-background ${
                                hop.suspicious ? "bg-destructive" : "bg-primary"
                              }`} />

                              <div className="bg-background/40 border border-border/50 p-2.5 rounded font-mono text-xs flex justify-between items-start">
                                <div className="min-w-0 flex-grow pr-2">
                                  <span className="text-[9px] text-primary font-bold">HOP {hop.step}</span>
                                  <span className="block text-foreground mt-0.5 truncate max-w-[140px] sm:max-w-[280px] font-semibold" title={hop.from}>
                                    FROM: {hop.from}
                                  </span>
                                  <span className="block text-muted-foreground text-[8px] mt-0.5">
                                    BY: {hop.by}
                                  </span>
                                </div>
                                <div className="text-right">
                                  <span className="text-[8px] text-muted-foreground block">+{hop.delay}s</span>
                                  {hop.suspicious && (
                                    <Badge className="bg-destructive/10 border border-destructive/30 text-destructive text-[8px] px-1.5 mt-1 font-mono">
                                      SUSPICIOUS
                                    </Badge>
                                  )}
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>

                        <div className="mt-2 flex flex-col gap-2 border-t border-border pt-4">
                          <span className="font-mono text-[9px] text-muted-foreground font-bold">SMTP ANOMALY AUDIT:</span>
                          <div className="flex flex-col gap-1.5 font-mono text-[10px] text-slate-300">
                            {phishingReport.analysis.map((find, idx) => (
                              <div key={idx} className="flex gap-2 items-start">
                                <span className="text-destructive font-bold">&gt;</span>
                                <span>{find}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </CardContent>
                    </Card>

                  </div>
                ) : (
                  <Card className="border-border bg-card/65 backdrop-blur-sm p-12 text-center text-muted-foreground font-mono text-xs shadow-xl flex flex-col items-center justify-center min-h-[300px]">
                    <Server className="size-8 text-muted/30 mb-2" />
                    No headers parsed. Paste email headers to audit.
                  </Card>
                )}
              </div>
            </div>
          )}

          {/* SECTION 4: THREAT RELATION GRAPH */}
          {currentSection === "graph" && (
            <div className="animate-fade-in flex flex-col gap-6">
              <Card className="border-border bg-card/65 backdrop-blur-sm shadow-xl flex flex-col overflow-hidden">
                <CardHeader className="pb-3 border-b border-border bg-background/25">
                  <CardTitle className="font-mono text-xs text-primary flex items-center gap-2">
                    <Share2 className="size-4" /> DYNAMIC INVESTIGATION CANVAS
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Full-width relationship topology. Click nodes to inspect details. Green = Clean, Yellow = Suspicious, Red = Malicious.
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-0 bg-[#04060f]/60 relative min-h-[460px] flex items-center justify-center">
                  
                  {threatReports.length === 0 ? (
                    <div className="text-center font-mono text-xs text-muted-foreground flex flex-col items-center justify-center p-8">
                      <Share2 className="size-8 text-muted/30 mb-2" />
                      No threat reports compiled. Triage logs to generate canvas.
                    </div>
                  ) : (
                    <div className="w-full h-full min-h-[460px] overflow-auto flex items-center justify-center relative">
                      <svg viewBox="0 0 700 420" className="w-full h-auto max-w-[700px] p-4">
                        <defs>
                          <marker id="arrow" viewBox="0 0 10 10" refX="18" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                            <path d="M 0 0 L 10 5 L 0 10 z" fill="#1e293b" />
                          </marker>
                          <marker id="arrow-malicious" viewBox="0 0 10 10" refX="18" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                            <path d="M 0 0 L 10 5 L 0 10 z" fill="#f43f5e" />
                          </marker>
                        </defs>

                        {/* RENDER LINKS */}
                        {graph.links.map((link, idx) => {
                          const srcNode = graph.nodes.find(n => n.id === link.source) || { x: graph.centerX, y: graph.centerY, status: "incident" };
                          const tgtNode = graph.nodes.find(n => n.id === link.target) || { x: graph.centerX, y: graph.centerY, status: "incident" };
                          const isMaliciousLink = srcNode.status === "malicious" || tgtNode.status === "malicious";

                          return (
                            <line
                              key={`link-${idx}`}
                              x1={srcNode.x}
                              y1={srcNode.y}
                              x2={tgtNode.x}
                              y2={tgtNode.y}
                              stroke={isMaliciousLink ? "#f43f5e" : "#1e293b"}
                              strokeWidth={isMaliciousLink ? "2" : "1.5"}
                              strokeDasharray={isMaliciousLink ? "4 4" : "0"}
                              markerEnd={isMaliciousLink ? "url(#arrow-malicious)" : "url(#arrow)"}
                            />
                          );
                        })}

                        {/* CENTER INCIDENT NODE */}
                        <g 
                          transform={`translate(${graph.centerX}, ${graph.centerY})`} 
                          onClick={() => setSelectedNode({ id: "INCIDENT-ALERT", type: "hash", label: "INCIDENT ALERT", data: { details: "Central event source alert node parsed." } })}
                          className="cursor-pointer"
                        >
                          <circle r="24" className="fill-slate-950 stroke-primary border-glow-green" strokeWidth="2.5" />
                          <ShieldAlert className="text-primary size-5 -translate-x-2.5 -translate-y-2.5" />
                        </g>

                        {/* RENDER SURROUNDING NODES */}
                        {graph.nodes.map((node) => {
                          const nodeColorClass = 
                            node.status === "malicious" ? "stroke-destructive fill-slate-950" : 
                            node.status === "suspicious" ? "stroke-amber-500 fill-slate-950" : "stroke-emerald-500 fill-slate-950";

                          return (
                            <g 
                              key={node.id} 
                              transform={`translate(${node.x}, ${node.y})`}
                              onClick={() => {
                                const report = threatReports.find(r => r.indicator === node.id);
                                setSelectedNode({ id: node.id, type: node.type, label: node.id, data: report });
                                if (report) setSelectedReport(report);
                              }}
                              className="cursor-pointer group"
                            >
                              <circle 
                                r="18" 
                                className={`${nodeColorClass} hover:stroke-white transition-all`} 
                                strokeWidth="2.5" 
                              />
                              
                              {node.type === "ip" && <Globe className="text-slate-400 size-4.5 -translate-x-2.25 -translate-y-2.25 group-hover:text-white" />}
                              {node.type === "domain" && <Globe className="text-slate-400 size-4.5 -translate-x-2.25 -translate-y-2.25 group-hover:text-white" />}
                              {node.type === "hash" && <Hash className="text-slate-400 size-4.5 -translate-x-2.25 -translate-y-2.25 group-hover:text-white" />}
                              {node.type === "url" && <LinkIcon className="text-slate-400 size-4.5 -translate-x-2.25 -translate-y-2.25 group-hover:text-white" />}

                              {/* Label text */}
                              <text 
                                y="28" 
                                textAnchor="middle" 
                                className="font-mono text-[9px] fill-slate-300 font-bold bg-slate-950 px-1 py-0.5 rounded"
                              >
                                {node.label}
                              </text>
                            </g>
                          );
                        })}
                      </svg>

                      {/* Floating details box */}
                      {selectedNode && (
                        <div className="absolute bottom-4 right-4 bg-slate-950/95 border border-border p-3.5 rounded-md font-mono text-[10px] w-72 shadow-2xl flex flex-col gap-2 z-20">
                          <div className="flex justify-between items-center border-b border-border pb-1">
                            <span className="text-primary glow-green font-bold uppercase">{selectedNode.type} Details</span>
                            <button onClick={() => setSelectedNode(null)} className="text-muted-foreground hover:text-white">
                              <X className="size-3" />
                            </button>
                          </div>
                          <p className="text-white font-bold break-all text-xs">{selectedNode.id}</p>
                          <p className="text-slate-400 leading-normal">
                            {selectedNode.data?.details || "Selected node is verified connected indicator."}
                          </p>
                          {selectedNode.data?.score !== undefined && (
                            <span className={`font-bold block mt-1 ${
                              selectedNode.data.status === "malicious" ? "text-destructive" :
                              selectedNode.data.status === "suspicious" ? "text-amber-500" : "text-emerald-500"
                            }`}>
                              Reputation: {selectedNode.data.score}% {selectedNode.data.status.toUpperCase()}
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          )}

          {/* SECTION 5: AI INCIDENT PLAYBOOK */}
          {currentSection === "playbook" && (
            <div className="animate-fade-in flex flex-col gap-6">
              <Card className="border-border bg-card/65 backdrop-blur-sm shadow-xl flex flex-col">
                <CardHeader className="pb-3 border-b border-border bg-background/25 flex flex-row justify-between items-center">
                  <div>
                    <CardTitle className="font-mono text-xs text-primary flex items-center gap-2">
                      <Terminal className="size-4 animate-pulse text-primary glow-green" /> AUTOMATED ACTION SCRIPT PLAYBOOK
                    </CardTitle>
                    <CardDescription className="text-xs">
                      Exportable rules for Firewalls, SIEM search configurations, and NIDS telemetry blocks.
                    </CardDescription>
                  </div>
                  <div className="flex gap-2">
                    <Button onClick={handleExportPlaybook} className="bg-primary text-background hover:bg-primary/80 font-mono text-xs flex gap-1.5 items-center">
                      <Download className="size-3.5" /> EXPORT REPORT
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="pt-4 flex-grow flex flex-col gap-6">
                  
                  {threatReports.length === 0 ? (
                    <div className="p-8 text-center text-muted-foreground font-mono text-xs flex flex-col items-center justify-center min-h-[200px]">
                      <FileText className="size-8 text-muted/30 mb-2" />
                      No threat rules compiled. Run log triage workspace first.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 font-mono text-xs">
                      
                      {/* Left: Palo Alto & Fortinet rules */}
                      <div className="flex flex-col gap-4">
                        <div>
                          <div className="flex justify-between items-center mb-1 text-[10px] text-primary">
                            <span>PALO ALTO CLI ADDR CONFIGS</span>
                            <button 
                              onClick={() => {
                                const txt = threatReports.filter(r => r.status === "malicious" && r.type === "ip").map(r => `set shared address Aegis-Block-${r.indicator} ip-netmask ${r.indicator}`).join("\n");
                                copyToClipboard(txt, "palo-alto");
                              }}
                              className="text-muted-foreground hover:text-white flex gap-1 items-center"
                            >
                              {copiedIndicator === "palo-alto" ? <Check className="size-3 text-primary" /> : <Clipboard className="size-3" />}
                              {copiedIndicator === "palo-alto" ? "COPIED" : "COPY"}
                            </button>
                          </div>
                          <pre className="bg-background/80 p-3 rounded border border-border text-[10px] text-slate-300 max-h-[140px] overflow-auto leading-relaxed select-text">
                            {threatReports.filter(r => r.status === "malicious" && r.type === "ip").length > 0 ? (
                              threatReports.filter(r => r.status === "malicious" && r.type === "ip").map(r => `set shared address Aegis-Block-${r.indicator} ip-netmask ${r.indicator}`).join("\n")
                            ) : (
                              "# No malicious IP indicators discovered to configure block rules."
                            )}
                          </pre>
                        </div>

                        <div>
                          <div className="flex justify-between items-center mb-1 text-[10px] text-accent">
                            <span>FORTINET CONTEXT FIREWALL CONFIGS</span>
                            <button 
                              onClick={() => {
                                const txt = threatReports.filter(r => r.status === "malicious" && r.type === "ip").map(r => `config firewall address\n  edit Aegis-Block-${r.indicator}\n  set subnet ${r.indicator} 255.255.255.255\n  end`).join("\n");
                                copyToClipboard(txt, "fortinet");
                              }}
                              className="text-muted-foreground hover:text-white flex gap-1 items-center"
                            >
                              {copiedIndicator === "fortinet" ? <Check className="size-3 text-accent" /> : <Clipboard className="size-3" />}
                              {copiedIndicator === "fortinet" ? "COPIED" : "COPY"}
                            </button>
                          </div>
                          <pre className="bg-background/80 p-3 rounded border border-border text-[10px] text-slate-300 max-h-[140px] overflow-auto leading-relaxed select-text">
                            {threatReports.filter(r => r.status === "malicious" && r.type === "ip").length > 0 ? (
                              threatReports.filter(r => r.status === "malicious" && r.type === "ip").map(r => `config firewall address\n  edit Aegis-Block-${r.indicator}\n  set subnet ${r.indicator} 255.255.255.255\n  end`).join("\n")
                            ) : (
                              "# No malicious IP indicators discovered."
                            )}
                          </pre>
                        </div>
                      </div>

                      {/* Right: Snort & Splunk configs */}
                      <div className="flex flex-col gap-4">
                        <div>
                          <div className="flex justify-between items-center mb-1 text-[10px] text-destructive">
                            <span>SURICATA / SNORT NIDS DETECTION RULES</span>
                            <button 
                              onClick={() => {
                                const txt = threatReports.filter(r => r.status === "malicious" && r.type === "ip").map(r => `drop ip ${r.indicator} any -> any any (msg:"AegisFlow malicious IP Blocked"; sid:1000001; rev:1;)`).join("\n");
                                copyToClipboard(txt, "snort");
                              }}
                              className="text-muted-foreground hover:text-white flex gap-1 items-center"
                            >
                              {copiedIndicator === "snort" ? <Check className="size-3 text-destructive" /> : <Clipboard className="size-3" />}
                              {copiedIndicator === "snort" ? "COPIED" : "COPY"}
                            </button>
                          </div>
                          <pre className="bg-background/80 p-3 rounded border border-border text-[10px] text-slate-300 max-h-[140px] overflow-auto leading-relaxed select-text">
                            {threatReports.filter(r => r.status === "malicious" && r.type === "ip").length > 0 ? (
                              threatReports.filter(r => r.status === "malicious" && r.type === "ip").map(r => `drop ip ${r.indicator} any -> any any (msg:"AegisFlow malicious IP Blocked"; sid:1000001; rev:1;)`).join("\n")
                            ) : (
                              "# No malicious IP indicators discovered."
                            )}
                          </pre>
                        </div>

                        <div>
                          <div className="flex justify-between items-center mb-1 text-[10px] text-primary">
                            <span>SPLUNK SIEM HUNT QUERIES</span>
                            <button 
                              onClick={() => {
                                const ips = threatReports.filter(r => r.status === "malicious").map(r => `"${r.indicator}"`).join(" OR ");
                                const txt = `index=security (${ips})`;
                                copyToClipboard(txt, "splunk");
                              }}
                              className="text-muted-foreground hover:text-white flex gap-1 items-center"
                            >
                              {copiedIndicator === "splunk" ? <Check className="size-3 text-primary" /> : <Clipboard className="size-3" />}
                              {copiedIndicator === "splunk" ? "COPIED" : "COPY"}
                            </button>
                          </div>
                          <pre className="bg-background/80 p-3 rounded border border-border text-[10px] text-slate-300 max-h-[140px] overflow-auto leading-relaxed select-text">
                            {threatReports.filter(r => r.status === "malicious").length > 0 ? (
                              `index=security (${threatReports.filter(r => r.status === "malicious").map(r => `"${r.indicator}"`).join(" OR ")})`
                            ) : (
                              "# No malicious indicators discovered to execute SIEM threat hunting query."
                            )}
                          </pre>
                        </div>
                      </div>

                      {/* Bottom AI incident summary generation */}
                      <div className="col-span-1 lg:col-span-2 border-t border-border pt-4">
                        <div className="flex justify-between items-center mb-1">
                          <span className="text-[10px] text-primary glow-green font-bold block">AI-GENERATED EXECUTIVE SECURITY REPORT SUMMARY</span>
                          <button 
                            onClick={() => {
                              const txt = document.getElementById("ai-report-body")?.innerText || "";
                              copyToClipboard(txt, "ai-report");
                            }}
                            className="text-muted-foreground hover:text-white flex gap-1 items-center font-mono text-[9px]"
                          >
                            {copiedIndicator === "ai-report" ? <Check className="size-3 text-primary" /> : <Clipboard className="size-3" />}
                            {copiedIndicator === "ai-report" ? "COPIED SUMMARY" : "COPY SUMMARY"}
                          </button>
                        </div>
                        <div id="ai-report-body" className="bg-[#04060f]/60 p-4 rounded-md border border-border leading-relaxed text-slate-300 text-[11px] select-text">
                          <p className="mb-2"><strong>INCIDENT TIMELINE SUMMARY:</strong></p>
                          <p className="mb-2">
                            An automated AegisFlow telemetry parsing audit identified <strong>{threatReports.length} indicators</strong>. 
                            Security checks confirmed <strong>{activeMalCount} malicious components</strong>.
                          </p>
                          <ul className="list-disc pl-4 flex flex-col gap-1.5">
                            {threatReports.filter(r => r.status === "malicious").map((r, i) => (
                              <li key={i}>
                                Detected malicious <strong>{r.type.toUpperCase()}</strong>: <code className="bg-slate-900 px-1 py-0.5 rounded text-destructive font-mono">{r.indicator}</code> - {r.details}
                              </li>
                            ))}
                          </ul>
                          <p className="mt-3 text-[10px] text-muted-foreground">
                            NIST incident response protocols dictate immediate isolation of infected hosts containing malicious SHA256 and initiating firewalls rule updates using configured configurations.
                          </p>
                        </div>
                      </div>

                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          )}

        </main>
      </div>

    </div>
  );
}

// Sub-Component: SettingsForm for API Keys
function SettingsForm({ keys, onSave, onClose }: { keys: ApiKeys; onSave: (k: ApiKeys) => void; onClose: () => void }) {
  const [vtKey, setVtKey] = useState(keys.virusTotal);
  const [ipdbKey, setIpdbKey] = useState(keys.abuseIPDB);
  const [otxKey, setOtxKey] = useState(keys.alienVaultOTX);

  return (
    <div className="flex flex-col gap-4 font-mono text-xs pt-2">
      <div className="flex flex-col gap-1.5">
        <label htmlFor="vt" className="text-[10px] text-primary">VIRUSTOTAL API KEY:</label>
        <Input 
          id="vt"
          type="password" 
          value={vtKey} 
          onChange={(e) => setVtKey(e.target.value)} 
          placeholder="Enter VirusTotal key..." 
          className="bg-background border-border text-xs focus-visible:ring-primary focus-visible:ring-1"
        />
      </div>

      <div className="flex flex-col gap-1.5">
        <label htmlFor="ipdb" className="text-[10px] text-primary">ABUSEIPDB API KEY:</label>
        <Input 
          id="ipdb"
          type="password" 
          value={ipdbKey} 
          onChange={(e) => setIpdbKey(e.target.value)} 
          placeholder="Enter AbuseIPDB key..." 
          className="bg-background border-border text-xs focus-visible:ring-primary focus-visible:ring-1"
        />
      </div>

      <div className="flex flex-col gap-1.5">
        <label htmlFor="otx" className="text-[10px] text-primary">ALIENVAULT OTX KEY:</label>
        <Input 
          id="otx"
          type="password" 
          value={otxKey} 
          onChange={(e) => setOtxKey(e.target.value)} 
          placeholder="Enter AlienVault OTX key..." 
          className="bg-background border-border text-xs focus-visible:ring-primary focus-visible:ring-1"
        />
      </div>

      <div className="flex gap-2 justify-end mt-4">
        <Button variant="outline" onClick={onClose} className="border-border hover:bg-secondary text-xs">
          CANCEL
        </Button>
        <Button onClick={() => onSave({ virusTotal: vtKey, abuseIPDB: ipdbKey, alienVaultOTX: otxKey })} className="bg-primary text-background hover:bg-primary/80 text-xs">
          SAVE KEYS
        </Button>
      </div>
    </div>
  );
}
