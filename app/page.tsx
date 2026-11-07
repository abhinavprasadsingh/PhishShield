"use client";

import { ChangeEvent, FormEvent, useMemo, useState } from "react";

type Analysis = {
  url: string;
  risk_label: string;
  risk_score: number;
  reasons: string[];
  prediction: number | null;
  phishing_probability: number | null;
  model_confidence: number | null;
  feature_importance: { feature: string; importance: number }[];
  mode: string;
  features: Record<string, number>;
  reputation?: { verdict: string; checks: { provider: string; status: string; message: string; malicious?: number; suspicious?: number; engines_total?: number; threat_types?: string[] }[] };
};
type CsvRow = { url: string; model_result: string; model_confidence: number | null; rule_score: number | string; warning_signals: string; validation: string };
type HistoryRow = { scannedAt: string; url: string; hostname: string; score: number; reasons: string[] };
type DomainInfo = { hostname: string; scheme: string; hostType: string; subdomains: number; port: string; pathLength: number; hasQuery: boolean; rootHint: string };

const featureLabels: Record<string, string> = {
  url_length: "URL length", hostname_length: "Hostname length", dot_count: "Dot count",
  hyphen_count: "Hyphen count", digit_count: "Digit count", at_count: "@ symbols",
  question_count: "Question marks", dash_count: "Hyphens", uses_https: "HTTPS enabled",
  has_ip_host: "IP address host", subdomain_count: "Subdomains",
  has_suspicious_word: "Suspicious keyword", has_url_shortener: "URL shortener",
  path_length: "Path length", query_length: "Query length"
};

async function readApiJson(response: Response) {
  const body = await response.text();
  try {
    return JSON.parse(body);
  } catch {
    throw new Error(
      `The API returned a non-JSON response (HTTP ${response.status}). The server route may be unavailable; please retry in a moment.`
    );
  }
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [csvRows, setCsvRows] = useState<CsvRow[]>([]);
  const [csvName, setCsvName] = useState("");
  const [csvBusy, setCsvBusy] = useState(false);
  const [csvMessage, setCsvMessage] = useState("");
  const [tab, setTab] = useState<"scanner" | "batch" | "domain" | "history" | "model">("scanner");
  const [history, setHistory] = useState<HistoryRow[]>([]);
  const [domainInput, setDomainInput] = useState("");
  const [domainInfo, setDomainInfo] = useState<DomainInfo | null>(null);
  const [domainError, setDomainError] = useState("");

  const riskClass = useMemo(() => {
    if (!analysis) return "";
    return analysis.risk_score >= 45 ? "danger" : analysis.risk_score >= 15 ? "warning" : "safe";
  }, [analysis]);

  async function analyzeUrl(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true); setError(""); setAnalysis(null);
    try {
      const response = await fetch("/api/analyze", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });
      const data = await readApiJson(response);
      if (!response.ok) throw new Error(data.detail || "Unable to analyze this URL.");
      setAnalysis(data);
      const parsed = new URL(data.url);
      setHistory(prev => [...prev, { scannedAt: new Date().toISOString(), url: data.url, hostname: parsed.hostname, score: data.risk_score, reasons: data.reasons }].slice(-200));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong. Try again.");
    } finally { setLoading(false); }
  }

  async function uploadCsv(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setCsvBusy(true); setCsvMessage(""); setCsvRows([]); setCsvName(file.name);
    try {
      const csv_text = await file.text();
      const response = await fetch("/api/scan-csv", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ csv_text })
      });
      const data = await readApiJson(response);
      if (!response.ok) throw new Error(data.detail || "Unable to scan this CSV.");
      setCsvRows(data.rows);
      setCsvMessage(`Scanned ${data.scanned} URLs · Skipped ${data.skipped}${data.scanned + data.skipped >= data.limit ? " · 1,000-row limit reached" : ""}`);
    } catch (err) {
      setCsvMessage(err instanceof Error ? err.message : "CSV scan failed.");
    } finally { setCsvBusy(false); event.target.value = ""; }
  }

  function downloadCsv() {
    if (!csvRows.length) return;
    const headers = ["url", "model_result", "model_confidence", "rule_score", "warning_signals", "validation"];
    const quote = (value: unknown) => '"' + String(value ?? "").replace(/"/g, '""') + '"';
    const content = [headers.join(","), ...csvRows.map(row => headers.map(key => quote(row[key as keyof CsvRow])).join(","))].join("\n");
    const blob = new Blob([content], { type: "text/csv;charset=utf-8" });
    const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = "phishshield-scan-results.csv"; link.click(); URL.revokeObjectURL(link.href);
  }

  return (
    <main className="shell">
      <aside className="sidebar">
        <a className="brand" href="#"><span className="brand-mark">⌁</span><span>PHISH<span className="brand-accent">SHIELD</span><small>URL INTELLIGENCE</small></span></a>
        <div className="side-label">WORKSPACE</div>
        <button className={tab === "scanner" ? "nav-item active" : "nav-item"} onClick={() => setTab("scanner")}><span>⌕</span> URL scanner</button>
        <button className={tab === "batch" ? "nav-item active" : "nav-item"} onClick={() => setTab("batch")}><span>▤</span> Batch analysis</button>
        <button className={tab === "domain" ? "nav-item active" : "nav-item"} onClick={() => setTab("domain")}><span>◎</span> Domain intelligence</button>
        <button className={tab === "history" ? "nav-item active" : "nav-item"} onClick={() => setTab("history")}><span>◷</span> History & analytics</button>
        <button className={tab === "model" ? "nav-item active" : "nav-item"} onClick={() => setTab("model")}><span>▥</span> Model dashboard</button>
        <div className="side-bottom"><span className="status-dot" /> SYSTEM READY <small>PhishShield engine · v1.0</small></div>
      </aside>

      <section className="main-area">
        <header className="topbar"><div><span className="live-dot" /> THREAT AWARENESS PLATFORM</div><span className="top-pill">PYTHON ENGINE <b>●</b></span></header>
        <div className="content">
          <section className="hero">
            <div className="hero-orbit orbit-one" /><div className="hero-orbit orbit-two" />
            <div className="eyebrow"><span className="eyebrow-line" /> URL INTELLIGENCE · THREAT INSPECTION</div>
            <h1>Stay one step<br /><span>ahead of the bait.</span></h1>
            <p>Inspect suspicious links, uncover hidden warning signs, and make smarter decisions before you click. URL structure is analyzed locally. Optional threat-intelligence providers receive the submitted URL for reputation lookups; PhishShield does not open the destination.</p>
            <div className="hero-tags"><span>✳ Explainable signals</span><span>⌁ No destination visits</span><span>◈ Python-powered analysis</span></div>
          </section>

          <div className="section-heading"><div><div className="eyebrow">YOUR SECURITY WORKSPACE</div><h2>{{scanner:"URL scanner",batch:"Batch analysis",domain:"Domain intelligence",history:"History & analytics",model:"Model dashboard"}[tab]}</h2></div><span className="secure-chip"><i /> PRIVATE BY DESIGN</span></div>

          {tab === "scanner" ? <>
            <section className="scan-card">
              <div className="card-top"><div><span className="card-icon">⌕</span><div><h3>Inspect a suspicious URL</h3><p>Paste a link below to check its structure and warning signals.</p></div></div><span className="step-label">01 / SCAN</span></div>
              <form onSubmit={analyzeUrl}>
                <label className="input-label" htmlFor="url">URL TO INSPECT</label>
                <div className="input-row"><span className="input-prefix">↗</span><input id="url" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com/login" maxLength={2048} autoComplete="url" /><button className="analyze-button" disabled={loading || !url.trim()}>{loading ? <><span className="spinner" /> ANALYZING</> : <>ANALYZE URL <span>↗</span></>}</button></div>
                <div className="input-foot"><span>↳ HTTP and HTTPS URLs supported</span><span>{url.length}/2048</span></div>
              </form>
              {error && <div className="error-box">⚠ {error}</div>}
              <div className="examples"><span>TRY AN EXAMPLE</span><button onClick={() => setUrl("https://www.google.com")}>google.com</button><button onClick={() => setUrl("http://secure-login-verify.example.test/account")}>suspicious login URL</button></div>
            </section>

            {analysis && <section className="results">
              <div className="result-head"><div><div className="eyebrow">ANALYSIS COMPLETE</div><h2>Inspection report</h2><p className="result-url">{analysis.url}</p></div><span className={`risk-pill ${riskClass}`}>{analysis.risk_label}</span></div>
              <div className="result-grid">
                <div className="score-card"><span className="mini-label">HEURISTIC SIGNAL SCORE</span><div className={`score-number ${riskClass}`}>{analysis.risk_score}<small>/100</small></div><div className="meter"><span className={riskClass} style={{ width: `${analysis.risk_score}%` }} /></div><p>Higher scores mean more URL warning patterns were found. This is not a calibrated probability.</p></div>
                <div className="reason-card"><span className="mini-label">WHAT WE NOTICED</span>{analysis.reasons.map((reason, i) => <div className="reason" key={i}><span>!</span>{reason}</div>)}</div>
              </div>
              {analysis.reputation && <div className="feature-card reputation-card">
                <div className="feature-title"><div><span className="mini-label">THREAT INTELLIGENCE</span><h3>{analysis.reputation.verdict === "threat_detected" ? "Known threat detected" : analysis.reputation.verdict === "no_known_threats_detected" ? "No known threats detected" : "Inconclusive — more checks needed"}</h3></div><span className={analysis.reputation.verdict === "threat_detected" ? "risk-pill danger" : analysis.reputation.verdict === "no_known_threats_detected" ? "risk-pill safe" : "risk-pill warning"}>{analysis.reputation.verdict === "threat_detected" ? "THREAT" : analysis.reputation.verdict === "no_known_threats_detected" ? "NO MATCHES" : "INCOMPLETE"}</span></div>
                <div className="reputation-list">{analysis.reputation.checks.map((check) => <div className="reason" key={check.provider}><span>{check.status === "malicious" ? "!" : check.status === "clean" ? "✓" : "?"}</span><div><b>{check.provider}</b><br />{check.message}{check.engines_total ? ` · ${check.malicious || 0} malicious / ${check.engines_total} engines` : ""}{check.threat_types?.length ? ` · ${check.threat_types.join(", ")}` : ""}</div></div>)}</div>
                <p className="disclaimer">A clean lookup means no match was found in the checked data at this time. It does not prove a website is safe. Unconfigured or unavailable services never count as clean.</p>
              </div>}
              {analysis.prediction !== null && <div className="score-card model-result-card"><span className="mini-label">TRAINED MODEL OUTPUT</span><h3>{analysis.prediction === 1 ? "Potential phishing" : "Model classifies as likely legitimate"}</h3><p>Model confidence: {analysis.model_confidence == null ? "Not available" : `${analysis.model_confidence}%`} · This is not a probability that the URL is safe.</p>{analysis.feature_importance.length > 0 && <div className="importance-list">{analysis.feature_importance.map(item=><div className="importance-row" key={item.feature}><span>{item.feature}</span><b>{item.importance.toFixed(3)}</b></div>)}</div>}</div>}
              <div className="feature-card"><div className="feature-title"><div><span className="mini-label">URL FEATURE BREAKDOWN</span><h3>Extracted signals</h3></div><span className="mode-chip">{analysis.mode}</span></div><div className="feature-grid">{Object.entries(analysis.features).map(([key, value]) => <div className="feature" key={key}><span>{featureLabels[key] || key}</span><b>{value}</b></div>)}</div></div>
              <div className="disclaimer">ⓘ A low-risk result does not guarantee a website is safe. HTTPS alone does not prove legitimacy. Do not submit links containing private tokens or session IDs.</div>
            </section>}
          </> : tab === "batch" ? <section className="scan-card batch-card">
            <div className="card-top"><div><span className="card-icon">▤</span><div><h3>Analyze a URL list</h3><p>Upload a CSV containing a column named <code>url</code>. Up to 1,000 URLs are supported per file.</p></div></div><span className="step-label">02 / BATCH</span></div>
            <label className="dropzone"><input type="file" accept=".csv,text/csv" onChange={uploadCsv} /><span className="upload-icon">↑</span><b>{csvBusy ? "Analyzing your file…" : csvName || "Choose a CSV file"}</b><small>CSV format · up to 1,000 URLs · 2 MB maximum</small></label>
            {csvBusy && <div className="loading-line"><span className="spinner" /> Processing URLs…</div>}
            {csvMessage && <div className="success-box">{csvMessage}</div>}
            {csvRows.length > 0 && <><div className="table-actions"><b>{csvRows.length} scan results</b><button className="download-button" onClick={downloadCsv}>↓ DOWNLOAD CSV</button></div><div className="table-wrap"><table><thead><tr><th>URL</th><th>MODEL RESULT</th><th>MODEL CONFIDENCE</th><th>RULE SCORE</th></tr></thead><tbody>{csvRows.map((row,i)=><tr key={i}><td className="url-cell">{row.url}</td><td>{row.model_result}</td><td>{row.model_confidence == null ? "—" : `${row.model_confidence}%`}</td><td>{row.rule_score === "" ? "—" : `${row.rule_score}/100`}</td></tr>)}</tbody></table></div></>}
          </section> : tab === "domain" ? <section className="scan-card batch-card">
            <div className="card-top"><div><span className="card-icon">◎</span><div><h3>Domain structure inspector</h3><p>Offline URL parsing only — no DNS, WHOIS, certificate, reputation or domain-age lookups.</p></div></div><span className="step-label">03 / DOMAIN</span></div>
            <form onSubmit={(event) => { event.preventDefault(); setDomainError(""); setDomainInfo(null); try { const raw = domainInput.trim(); if (!raw) throw new Error("Enter a URL first."); const parsed = new URL(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw) ? raw : "https://" + raw); if (!["http:","https:"].includes(parsed.protocol) || !parsed.hostname.includes(".")) throw new Error("Enter a valid HTTP or HTTPS URL."); const labels = parsed.hostname.toLowerCase().replace(/\.$/,"").split(".").filter(Boolean); const hostType = /^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname) ? "IP address" : "Domain hostname"; setDomainInfo({ hostname: parsed.hostname, scheme: parsed.protocol.replace(":","").toUpperCase(), hostType, subdomains: Math.max(0,labels.length-2), port: parsed.port || "Default / not specified", pathLength: parsed.pathname.length, hasQuery: Boolean(parsed.search), rootHint: labels.slice(-2).join(".") }); } catch(e) { setDomainError(e instanceof Error ? e.message : "Invalid URL."); } }}>
              <label className="input-label" htmlFor="domain-url">URL FOR DOMAIN BREAKDOWN</label>
              <div className="input-row"><span className="input-prefix">◎</span><input id="domain-url" value={domainInput} onChange={e=>setDomainInput(e.target.value)} placeholder="https://login.example.com/account"/><button className="analyze-button">INSPECT STRUCTURE ↗</button></div>
            </form>
            {domainError && <div className="error-box">⚠ {domainError}</div>}
            {domainInfo && <div className="feature-grid domain-grid">{Object.entries({"Hostname":domainInfo.hostname,"Scheme":domainInfo.scheme,"Hostname type":domainInfo.hostType,"Subdomain labels":domainInfo.subdomains,"Approx. last two labels":domainInfo.rootHint,"Port":domainInfo.port,"Path length":domainInfo.pathLength,"Query present":domainInfo.hasQuery?"Yes":"No"}).map(([key,value])=><div className="feature" key={key}><span>{key}</span><b>{value}</b></div>)}</div>}
            <div className="disclaimer">ⓘ The last-two-label hint is not always the registrable domain (for example, co.uk). HTTPS encrypts a connection but does not prove a site is legitimate.</div>
          </section> : tab === "history" ? <section className="scan-card batch-card">
            <div className="card-top"><div><span className="card-icon">◷</span><div><h3>Session scan history</h3><p>History stays in this browser tab's memory and is not saved to a database.</p></div></div><span className="step-label">04 / HISTORY</span></div>
            <div className="history-metrics"><div className="feature"><span>Scans this session</span><b>{history.length}</b></div><div className="feature"><span>Unique hostnames</span><b>{new Set(history.map(item=>item.hostname)).size}</b></div><div className="feature"><span>High rule signals (45+)</span><b>{history.filter(item=>item.score>=45).length}</b></div></div>
            {history.length ? <><div className="table-actions"><b>Recent scans</b><button className="download-button" onClick={()=>setHistory([])}>CLEAR HISTORY</button></div><div className="table-wrap"><table><thead><tr><th>SCANNED AT (UTC)</th><th>HOSTNAME</th><th>RULE SCORE</th><th>URL</th></tr></thead><tbody>{[...history].reverse().map((item,i)=><tr key={i}><td>{item.scannedAt.slice(0,19).replace("T"," ")}</td><td>{item.hostname}</td><td>{item.score}/100</td><td className="url-cell">{item.url}</td></tr>)}</tbody></table></div></> : <div className="success-box">No scans yet. Analyze a URL in the URL scanner to start your session history.</div>}
          </section> : <section className="scan-card batch-card">
            <div className="card-top"><div><span className="card-icon">▥</span><div><h3>Documented model evaluation</h3><p>Recorded held-out dataset metrics from the repository report, not a live measurement of the deployed model.</p></div></div><span className="step-label">05 / MODEL</span></div>
            <div className="feature-grid">{[["HistGradientBoosting","99.7%","99.9%","99.4%","99.6%"],["Random Forest","99.7%","99.8%","99.4%","99.6%"],["Logistic Regression","99.5%","99.9%","98.9%","99.4%"]].map((row,i)=><div className="feature model-metric" key={i}><b>{row[0]}</b><span>Accuracy {row[1]}</span><span>Precision {row[2]}</span><span>Recall {row[3]}</span><span>F1 {row[4]}</span></div>)}</div>
            <h3 className="matrix-title">Selected model confusion matrix</h3><div className="table-wrap"><table><thead><tr><th></th><th>PREDICTED LEGITIMATE</th><th>PREDICTED PHISHING</th></tr></thead><tbody><tr><td>ACTUAL LEGITIMATE</td><td>26,759</td><td>19</td></tr><tr><td>ACTUAL PHISHING</td><td>125</td><td>20,225</td></tr></tbody></table></div>
            <div className="disclaimer">ⓘ The model artifact is not committed to GitHub by default. These recorded metrics do not prove that the live app is using this trained model. See the evaluation report for methodology and limitations.</div>
          </section>}

          <section className="bottom-grid"><div className="info-card"><span className="info-icon">⌁</span><div><b>Text-only inspection</b><p>PhishShield parses URL structure and checks configured threat-intelligence sources. It does not open the destination itself.</p></div></div><div className="info-card"><span className="info-icon violet">◈</span><div><b>Explainable by design</b><p>See the URL signals behind each heuristic assessment.</p></div></div><div className="info-card"><span className="info-icon green">✳</span><div><b>Security is layered</b><p>Use this as one signal alongside browser protection and good judgment.</p></div></div></section>
          <footer>© 2026 PHISHSHIELD <span>BUILT FOR A SAFER INTERNET</span></footer>
        </div>
      </section>
    </main>
  );
}
