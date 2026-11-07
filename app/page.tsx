"use client";

import { ChangeEvent, FormEvent, useMemo, useState } from "react";

type Analysis = {
  url: string;
  risk_label: string;
  risk_score: number;
  reasons: string[];
  prediction: number | null;
  phishing_probability: number | null;
  mode: string;
  features: Record<string, number>;
};
type CsvRow = { url: string; label: string; risk_label: string; risk_score: number; mode: string };

const featureLabels: Record<string, string> = {
  url_length: "URL length", hostname_length: "Hostname length", dot_count: "Dot count",
  hyphen_count: "Hyphen count", digit_count: "Digit count", at_count: "@ symbols",
  question_count: "Question marks", dash_count: "Hyphens", uses_https: "HTTPS enabled",
  has_ip_host: "IP address host", subdomain_count: "Subdomains",
  has_suspicious_word: "Suspicious keyword", has_url_shortener: "URL shortener",
  path_length: "Path length", query_length: "Query length"
};

export default function Home() {
  const [url, setUrl] = useState("");
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [csvRows, setCsvRows] = useState<CsvRow[]>([]);
  const [csvName, setCsvName] = useState("");
  const [csvBusy, setCsvBusy] = useState(false);
  const [csvMessage, setCsvMessage] = useState("");
  const [tab, setTab] = useState<"scanner" | "batch">("scanner");

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
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Unable to analyze this URL.");
      setAnalysis(data);
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
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Unable to scan this CSV.");
      setCsvRows(data.rows);
      setCsvMessage(`Scanned ${data.scanned} URLs · Skipped ${data.skipped}${data.scanned + data.skipped >= data.limit ? " · 500-row limit reached" : ""}`);
    } catch (err) {
      setCsvMessage(err instanceof Error ? err.message : "CSV scan failed.");
    } finally { setCsvBusy(false); event.target.value = ""; }
  }

  function downloadCsv() {
    if (!csvRows.length) return;
    const headers = ["url", "label", "risk_label", "risk_score", "mode"];
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
        <div className="side-bottom"><span className="status-dot" /> SYSTEM READY <small>PhishShield engine · v1.0</small></div>
      </aside>

      <section className="main-area">
        <header className="topbar"><div><span className="live-dot" /> THREAT AWARENESS PLATFORM</div><span className="top-pill">PYTHON ENGINE <b>●</b></span></header>
        <div className="content">
          <section className="hero">
            <div className="hero-orbit orbit-one" /><div className="hero-orbit orbit-two" />
            <div className="eyebrow"><span className="eyebrow-line" /> URL INTELLIGENCE · THREAT INSPECTION</div>
            <h1>Stay one step<br /><span>ahead of the bait.</span></h1>
            <p>Inspect suspicious links, uncover hidden warning signs, and make smarter decisions before you click. Your submitted URL is analyzed as text — never opened.</p>
            <div className="hero-tags"><span>✳ Explainable signals</span><span>⌁ No destination visits</span><span>◈ Python-powered analysis</span></div>
          </section>

          <div className="section-heading"><div><div className="eyebrow">YOUR SECURITY WORKSPACE</div><h2>{tab === "scanner" ? "URL scanner" : "Batch analysis"}</h2></div><span className="secure-chip"><i /> PRIVATE BY DESIGN</span></div>

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
              <div className="feature-card"><div className="feature-title"><div><span className="mini-label">URL FEATURE BREAKDOWN</span><h3>Extracted signals</h3></div><span className="mode-chip">{analysis.mode}</span></div><div className="feature-grid">{Object.entries(analysis.features).map(([key, value]) => <div className="feature" key={key}><span>{featureLabels[key] || key}</span><b>{value}</b></div>)}</div></div>
              <div className="disclaimer">ⓘ A low-risk result does not guarantee a website is safe. HTTPS alone does not prove legitimacy. Do not submit links containing private tokens or session IDs.</div>
            </section>}
          </> : <section className="scan-card batch-card">
            <div className="card-top"><div><span className="card-icon">▤</span><div><h3>Analyze a URL list</h3><p>Upload a CSV with <code>url</code> and <code>label</code> columns (1 = phishing, 0 = legitimate).</p></div></div><span className="step-label">02 / BATCH</span></div>
            <label className="dropzone"><input type="file" accept=".csv,text/csv" onChange={uploadCsv} /><span className="upload-icon">↑</span><b>{csvBusy ? "Analyzing your file…" : csvName || "Choose a CSV file"}</b><small>CSV format · up to 500 URLs · 2 MB maximum</small></label>
            {csvBusy && <div className="loading-line"><span className="spinner" /> Processing URLs…</div>}
            {csvMessage && <div className="success-box">{csvMessage}</div>}
            {csvRows.length > 0 && <><div className="table-actions"><b>{csvRows.length} scan results</b><button className="download-button" onClick={downloadCsv}>↓ DOWNLOAD CSV</button></div><div className="table-wrap"><table><thead><tr><th>URL</th><th>RISK ASSESSMENT</th><th>SCORE</th></tr></thead><tbody>{csvRows.map((row,i)=><tr key={i}><td className="url-cell">{row.url}</td><td>{row.risk_label}</td><td>{row.risk_score}/100</td></tr>)}</tbody></table></div></>}
          </section>}

          <section className="bottom-grid"><div className="info-card"><span className="info-icon">⌁</span><div><b>Text-only inspection</b><p>PhishShield parses URL structure. It never visits the submitted destination.</p></div></div><div className="info-card"><span className="info-icon violet">◈</span><div><b>Explainable by design</b><p>See the URL signals behind each heuristic assessment.</p></div></div><div className="info-card"><span className="info-icon green">✳</span><div><b>Security is layered</b><p>Use this as one signal alongside browser protection and good judgment.</p></div></div></section>
          <footer>© 2026 PHISHSHIELD <span>BUILT FOR A SAFER INTERNET</span></footer>
        </div>
      </section>
    </main>
  );
}
