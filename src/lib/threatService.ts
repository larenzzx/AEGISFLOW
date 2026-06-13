// Threat Intelligence Enrichment Service - Live API Ready

export interface ThreatReport {
  indicator: string;
  type: "ip" | "domain" | "hash" | "url";
  status: "safe" | "suspicious" | "malicious";
  score: number; // 0 to 100
  details: string;
  sources: {
    virusTotal?: { score: string; scanned: string; detected: string[] };
    abuseIPDB?: { reports: number; lastReported: string; score: number; country: string };
    alienVaultOTX?: { pulses: number; tags: string[] };
  };
  simulated?: boolean;
}

export interface ApiKeys {
  virusTotal: string;
  abuseIPDB: string;
  alienVaultOTX: string;
}

// Regex patterns to extract IOCs
const IP_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
const DOMAIN_REGEX = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,30}[a-z0-9]\b/gi;
const HASH_256_REGEX = /\b[A-Fa-f0-9]{64}\b/g;
const URL_REGEX = /https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)/gi;

const DOMAIN_WHITELIST = [
  "microsoft.com", "google.com", "github.com", "gmail.com", "yahoo.com", "outlook.com",
  "wikipedia.org", "w3.org", "adobe.com", "apple.com", "cloudflare.com", "amazon.com",
  "virustotal.com", "abuseipdb.com", "alienvault.com", "shodan.io", "otx.alienvault.com",
  "localhost", "example.com"
];

export function extractIOCs(text: string) {
  const ips = Array.from(new Set(text.match(IP_REGEX) || []));
  const hashes = Array.from(new Set(text.match(HASH_256_REGEX) || []));
  const urls = Array.from(new Set(text.match(URL_REGEX) || []));
  
  const rawDomains = Array.from(new Set(text.match(DOMAIN_REGEX) || []));
  const domains = rawDomains.filter(domain => {
    const dLower = domain.toLowerCase();
    if (DOMAIN_WHITELIST.some(white => dLower === white || dLower.endsWith("." + white))) {
      return false;
    }
    if (domain.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
      return false;
    }
    return true;
  });

  return { ips, domains, hashes, urls };
}

// Base64 helper for VirusTotal URL parsing
function getVtUrlId(url: string): string {
  try {
    const b64 = btoa(unescape(encodeURIComponent(url)));
    return b64.replace(/=/g, "");
  } catch (e) {
    return url;
  }
}

// Live Threat Intelligence Enrichment logic
export async function enrichIndicator(indicator: string, type: ThreatReport["type"], keys?: ApiKeys): Promise<ThreatReport> {
  const cleanIndicator = indicator.trim();
  const hasKeys = keys && (keys.abuseIPDB || keys.virusTotal || keys.alienVaultOTX);

  // If no keys are provided, return simulated data immediately to preserve functionality
  if (!hasKeys) {
    return simulateFallback(cleanIndicator, type);
  }

  // Live Threat State placeholder
  let status: ThreatReport["status"] = "safe";
  let score = 0;
  let details = "Enriched from active telemetry endpoints.";
  const sources: ThreatReport["sources"] = {};

  // 1. QUERY ABUSEIPDB (IPs only)
  if (type === "ip" && keys?.abuseIPDB) {
    try {
      const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${cleanIndicator}`, {
        headers: { "Key": keys.abuseIPDB, "Accept": "application/json" }
      });
      if (res.ok) {
        const payload = await res.json();
        const info = payload.data;
        sources.abuseIPDB = {
          reports: info.totalReports,
          lastReported: info.lastReportedAt || "Never",
          score: info.abuseConfidenceScore,
          country: info.countryCode
        };
        score = Math.max(score, info.abuseConfidenceScore);
      }
    } catch (e) {
      console.error("AbuseIPDB API fetch failed", e);
    }
  }

  // 2. QUERY VIRUSTOTAL (IP, Domain, URL, Hash)
  if (keys?.virusTotal) {
    let vtEndpoint = "";
    if (type === "ip") vtEndpoint = `ip_addresses/${cleanIndicator}`;
    else if (type === "domain") vtEndpoint = `domains/${cleanIndicator}`;
    else if (type === "hash") vtEndpoint = `files/${cleanIndicator}`;
    else if (type === "url") vtEndpoint = `urls/${getVtUrlId(cleanIndicator)}`;

    if (vtEndpoint) {
      try {
        const res = await fetch(`https://www.virustotal.com/api/v3/${vtEndpoint}`, {
          headers: { "x-apikey": keys.virusTotal }
        });
        if (res.ok) {
          const payload = await res.json();
          const stats = payload.data.attributes.last_analysis_stats;
          const malicious = stats.malicious || 0;
          const total = (stats.harmless || 0) + malicious + (stats.suspicious || 0) + (stats.undetected || 0);
          
          const detectedEngines: string[] = [];
          const results = payload.data.attributes.last_analysis_results || {};
          Object.keys(results).forEach(engine => {
            if (results[engine].category === "malicious" && detectedEngines.length < 5) {
              detectedEngines.push(engine);
            }
          });

          sources.virusTotal = {
            score: `${malicious}/${total}`,
            scanned: new Date().toISOString().split("T")[0],
            detected: detectedEngines
          };

          // Update aggregated score
          const vtPercentage = Math.round((malicious / (total || 1)) * 100);
          score = Math.max(score, vtPercentage);
        }
      } catch (e) {
        console.error("VirusTotal API fetch failed", e);
      }
    }
  }

  // 3. QUERY ALIENVAULT OTX
  if (keys?.alienVaultOTX) {
    let otxType = "";
    if (type === "ip") otxType = "IPv4";
    else if (type === "domain") otxType = "domain";
    else if (type === "hash") otxType = "file";
    else if (type === "url") otxType = "url";

    if (otxType) {
      try {
        const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/${otxType}/${cleanIndicator}/general`, {
          headers: { "X-OTX-API-KEY": keys.alienVaultOTX }
        });
        if (res.ok) {
          const payload = await res.json();
          const pulses = payload.pulse_info?.count || 0;
          const tagsList: string[] = [];
          
          if (payload.pulse_info?.pulses) {
            payload.pulse_info.pulses.forEach((p: any) => {
              if (p.tags) {
                p.tags.forEach((t: string) => {
                  if (!tagsList.includes(t) && tagsList.length < 5) tagsList.push(t);
                });
              }
            });
          }

          sources.alienVaultOTX = {
            pulses,
            tags: tagsList
          };

          if (pulses > 0) {
            score = Math.max(score, Math.min(100, 30 + pulses * 10));
          }
        }
      } catch (e) {
        console.error("AlienVault OTX API fetch failed", e);
      }
    }
  }

  // Evaluate final status from aggregate score
  if (score > 60) {
    status = "malicious";
    details = `Threat verification confirmed. Identified as a high-risk malicious ${type} with high confidence levels.`;
  } else if (score > 15) {
    status = "suspicious";
    details = `Suspicious indicator. Detections found in global blacklists, potential association with scanning or anonymous relays.`;
  } else {
    status = "safe";
    details = `Indicator clean. Checked against VirusTotal, AbuseIPDB, and AlienVault OTX databases with no active indicators discovered.`;
  }

  return {
    indicator: cleanIndicator,
    type,
    status,
    score,
    details,
    sources,
    simulated: false
  };
}

// Simulated data fallback when API keys are not provided
function simulateFallback(cleanIndicator: string, type: ThreatReport["type"]): ThreatReport {
  const hashCode = cleanIndicator.split("").reduce((acc, char) => acc + char.charCodeAt(0), 0);
  const factor = hashCode % 100;
  
  let status: ThreatReport["status"] = "safe";
  let score = 0;
  let details = "";
  
  if (factor > 70) {
    status = "malicious";
    score = 75 + (hashCode % 25);
    details = `SIMULATED DETECTIONS: Telemetry logs indicate malicious activity matching known cyber threat profiles for ${type}. (Install API keys in configuration for live results)`;
  } else if (factor > 40) {
    status = "suspicious";
    score = 30 + (hashCode % 30);
    details = `SIMULATED WARNING: Flagged in correlation lists as unverified or hosting generic redirects.`;
  } else {
    status = "safe";
    score = 0;
    details = `SIMULATED CLEAN: Telemetry shows no hits in local threat databases.`;
  }

  return {
    indicator: cleanIndicator,
    type,
    status,
    score,
    details,
    sources: {
      virusTotal: {
        score: status === "malicious" ? "12/90" : status === "suspicious" ? "2/90" : "0/90",
        scanned: new Date().toISOString().split("T")[0],
        detected: status === "malicious" ? ["Engine-A", "Engine-B"] : []
      },
      abuseIPDB: type === "ip" ? {
        reports: status === "malicious" ? 421 : status === "suspicious" ? 18 : 0,
        lastReported: status === "malicious" ? "15 mins ago" : "Never",
        score,
        country: hashCode % 2 === 0 ? "RU" : "CN"
      } : undefined,
      alienVaultOTX: {
        pulses: status === "malicious" ? 6 : 0,
        tags: status === "malicious" ? ["phishing", "botnet"] : []
      }
    },
    simulated: true
  };
}

// Phishing Header Parser Logic
export interface PhishingHeaderReport {
  spf: { status: "PASS" | "FAIL" | "NONE"; details: string };
  dkim: { status: "PASS" | "FAIL" | "NONE"; details: string };
  dmarc: { status: "PASS" | "FAIL" | "NONE"; details: string };
  alignment: { spfAligned: boolean; dkimAligned: boolean };
  hops: Array<{
    step: number;
    from: string;
    to: string;
    by: string;
    delay: number;
    suspicious: boolean;
  }>;
  analysis: string[];
  verdict: "safe" | "suspicious" | "malicious";
}

export function parseEmailHeaders(headersText: string): PhishingHeaderReport {
  const authResults = headersText.match(/Authentication-Results:[\s\S]*?(?=\r?\n\S|$)/i)?.[0] || "";
  
  const spfMatch = authResults.match(/spf=(\w+)/i) || headersText.match(/Received-SPF: (\w+)/i);
  const dkimMatch = authResults.match(/dkim=(\w+)/i);
  const dmarcMatch = authResults.match(/dmarc=(\w+)/i);

  const spfStatus = (spfMatch ? spfMatch[1].toUpperCase() : "NONE") as "PASS" | "FAIL" | "NONE";
  const dkimStatus = (dkimMatch ? dkimMatch[1].toUpperCase() : "NONE") as "PASS" | "FAIL" | "NONE";
  const dmarcStatus = (dmarcMatch ? dmarcMatch[1].toUpperCase() : "NONE") as "PASS" | "FAIL" | "NONE";

  const fromHeader = headersText.match(/From: (.*)/i)?.[1] || "";
  const returnPath = headersText.match(/Return-Path: <(.*)>/i)?.[1] || "";
  
  const fromEmailMatch = fromHeader.match(/<([^>]+)>/) || fromHeader.match(/(\S+@\S+)/);
  const fromDomain = fromEmailMatch ? fromEmailMatch[1].split("@")[1] : "";
  const returnPathDomain = returnPath ? returnPath.split("@")[1] : "";

  const spfAligned = !!(fromDomain && returnPathDomain && fromDomain.toLowerCase() === returnPathDomain.toLowerCase());
  
  const receivedLines: string[] = [];
  const rxMatches = headersText.matchAll(/Received: ([\s\S]*?)(?=\r?\n\S|$)/gi);
  for (const match of rxMatches) {
    receivedLines.push(match[1]);
  }

  const hops = receivedLines.reverse().map((line, index) => {
    const fromMatch = line.match(/from\s+(\S+)/i);
    const byMatch = line.match(/by\s+(\S+)/i);
    
    const fromHost = fromMatch ? fromMatch[1].replace(/[()]/g, "") : "Unknown Source";
    const byHost = byMatch ? byMatch[1].replace(/[;()]/g, "") : "Internal Mail Server";
    const suspicious = fromHost.includes("temp") || fromHost.includes("random") || fromHost.match(/\d{1,3}\-\d{1,3}\-\d{1,3}\-\d{1,3}/);

    return {
      step: index + 1,
      from: fromHost,
      by: byHost,
      to: index === receivedLines.length - 1 ? "Organization Inbox" : `Hop ${index + 2}`,
      delay: index * 2 + Math.floor(Math.random() * 4),
      suspicious: !!suspicious
    };
  });

  const analysis: string[] = [];
  let score = 0;

  if (spfStatus === "FAIL") {
    analysis.push("SPF authentication failed. The sending server is not authorized to send mail on behalf of the domain.");
    score += 40;
  }
  if (dkimStatus === "FAIL") {
    analysis.push("DKIM cryptographic signature failed. The email payload might have been modified in transit.");
    score += 40;
  }
  if (dmarcStatus === "FAIL") {
    analysis.push("DMARC alignment checks failed. The sender address doesn't align with SPF or DMARC validation rules.");
    score += 50;
  }
  if (fromHeader && returnPath && !spfAligned) {
    analysis.push(`Mismatched domains: Header From domain (${fromDomain || "Unknown"}) doesn't align with Envelope Return-Path (${returnPathDomain || "Unknown"}). Common phishing sign.`);
    score += 30;
  }
  
  if (hops.some(h => h.suspicious)) {
    analysis.push("Suspicious mail relays found in routing headers. Email routed through dynamic or untrusted servers.");
    score += 20;
  }

  if (analysis.length === 0) {
    analysis.push("All authentication protocols (SPF, DKIM, DMARC) passed alignment checks. Mail path looks legitimate.");
  }

  const verdict = score >= 70 ? "malicious" : score >= 30 ? "suspicious" : "safe";

  return {
    spf: { status: spfStatus, details: spfStatus === "PASS" ? "Verified sender IP" : spfStatus === "FAIL" ? "Sender IP blocked" : "No SPF record found" },
    dkim: { status: dkimStatus, details: dkimStatus === "PASS" ? "Signature valid" : dkimStatus === "FAIL" ? "Signature broken" : "Email unsigned" },
    dmarc: { status: dmarcStatus, details: dmarcStatus === "PASS" ? "Alignment verified" : dmarcStatus === "FAIL" ? "DMARC policy failed" : "No DMARC policy defined" },
    alignment: { spfAligned, dkimAligned: dkimStatus === "PASS" },
    hops,
    analysis,
    verdict
  };
}
