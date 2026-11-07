from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

import streamlit as st
import streamlit.components.v1 as components

from src.csv_safety import sanitize_csv_for_spreadsheet

# Google Analytics 4 page-view tracking. Streamlit renders this snippet in
# a component iframe, so explicitly set the public app URL as page_location.
# This must be verified in GA4 Realtime after the app redeploys.
GA_MEASUREMENT_ID = "G-6L7WQYZ1LK"
GA_APP_URL = "https://phishsentinel.streamlit.app/"
components.html(
    f"""
    <script async src="https://www.googletagmanager.com/gtag/js?id={GA_MEASUREMENT_ID}"></script>
    <script>
      window.dataLayer = window.dataLayer || [];
      function gtag() {{ window.dataLayer.push(arguments); }}
      gtag('js', new Date());
      gtag('config', '{GA_MEASUREMENT_ID}', {{
        send_page_view: true,
        page_location: '{GA_APP_URL}',
        page_title: 'PhishShield'
      }});
    </script>
    """,
    height=1,
    width=1,
)

ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "models" / "phishing_model.joblib"
FEATURES = [
    "url_length", "hostname_length", "dot_count", "hyphen_count",
    "digit_count", "at_count", "question_count", "dash_count",
    "uses_https", "has_ip_host", "subdomain_count", "has_suspicious_word",
    "has_url_shortener", "path_length", "query_length",
]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
SUSPICIOUS = {"login", "verify", "account", "update", "secure", "password", "banking", "signin", "confirm", "wallet", "recover"}


def normalize_url(raw: str) -> str:
    """Validate a URL as text only; never make a network request."""
    value = raw.strip()
    if not value:
        raise ValueError("Enter a URL first.")
    if len(value) > 2048:
        raise ValueError("The URL is too long (maximum 2,048 characters).")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("The URL contains invalid control characters.")
    if any(ch.isspace() for ch in value):
        raise ValueError("The URL contains spaces. Check the address and try again.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    try:
        parsed = urlparse(value)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only http:// and https:// URLs can be checked.")
        if not parsed.hostname:
            raise ValueError("Enter a complete domain name, such as example.com.")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing embedded usernames or passwords are not accepted.")
        host = parsed.hostname.rstrip(".")
        if not host or "." not in host:
            raise ValueError("Enter a complete domain name, such as example.com.")
        # Accessing .port validates malformed and out-of-range ports.
        port = parsed.port
        if port is not None and not (1 <= port <= 65535):
            raise ValueError("The URL contains an invalid port.")
        # Reject malformed host labels while allowing valid internationalized domains.
        ascii_host = host.encode("idna").decode("ascii")
        if len(ascii_host) > 253:
            raise ValueError("The hostname is too long.")
        labels = ascii_host.split(".")
        if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
               or not re.fullmatch(r"[A-Za-z0-9-]+", label) for label in labels):
            raise ValueError("The hostname format is invalid.")
    except (UnicodeError, ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith(("Enter ", "Only ", "URLs ", "The URL", "The hostname")):
            raise
        raise ValueError("The URL format is invalid. Check the hostname and port.") from exc
    return value

def extract_features(raw: str) -> dict[str, int]:
    url = normalize_url(raw)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    labels = [part for part in host.split(".") if part]
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = 1
    except ValueError:
        is_ip = 0
    lowered = url.lower()
    return {
        "url_length": len(url),
        "hostname_length": len(host),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "digit_count": sum(c.isdigit() for c in url),
        "at_count": url.count("@"),
        "question_count": url.count("?"),
        "dash_count": url.count("-"),
        "uses_https": int(parsed.scheme.lower() == "https"),
        "has_ip_host": is_ip,
        "subdomain_count": max(0, len(labels) - 2),
        "has_suspicious_word": int(any(word in lowered for word in SUSPICIOUS)),
        "has_url_shortener": int(host in SHORTENERS),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
    }


def heuristic_assessment(features: dict[str, int]) -> tuple[str, int, list[str]]:
    reasons = []
    if features["has_ip_host"]:
        reasons.append("The hostname is an IP address rather than a typical domain.")
    if features["has_url_shortener"]:
        reasons.append("The hostname belongs to a known URL-shortening service, which can hide the final destination.")
    if features["has_suspicious_word"]:
        reasons.append("The URL contains a word often used in account or security lures.")
    if features["at_count"]:
        reasons.append("The URL contains an @ symbol, which can make the destination confusing.")
    if features["subdomain_count"] >= 3:
        reasons.append("The hostname has several subdomain levels. Check which domain actually owns the site.")
    if features["url_length"] >= 100:
        reasons.append("The URL is unusually long.")
    if features["hyphen_count"] >= 3:
        reasons.append("The URL contains multiple hyphens.")
    if not features["uses_https"]:
        reasons.append("The URL does not use HTTPS.")
    score = min(95, len(reasons) * 15)
    label = "Higher-risk signals" if score >= 45 else "Some caution advised" if score >= 15 else "Fewer obvious signals"
    if not reasons:
        reasons.append("No simple warning patterns were detected. This does not prove the site is safe.")
    return label, score, reasons


def load_model():
    if not MODEL_PATH.exists():
        return None
    try:
        import joblib
        return joblib.load(MODEL_PATH)
    except Exception:
        return None


st.set_page_config(page_title="PhishShield | Intelligent Phishing Detection", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');
:root { color-scheme: dark; }
html, body, [class*="css"] { font-family: 'DM Sans', sans-serif; }
.stApp { background: radial-gradient(ellipse at 12% -8%,rgba(26,108,133,.25),transparent 38%),radial-gradient(ellipse at 100% 30%,rgba(39,73,142,.16),transparent 34%),#070b12; color:#eaf1fb; }
.block-container { max-width:1260px; padding:1.25rem 1.6rem 3.5rem; }
[data-testid="stHeader"] { background:rgba(7,11,18,.72); }
/* Keep the hosted app chrome minimal; hide Streamlit's built-in header controls. */
[data-testid="stHeader"] { display: none; }
[data-testid="stToolbar"] { display: none !important; }
[data-testid="stDecoration"] { display: none !important; }

[data-testid="stSidebar"] { background:linear-gradient(180deg,#0c1725,#080e17); border-right:1px solid #1c3042; }
[data-testid="stSidebar"] > div { padding-top:1.5rem; }
.hero { position:relative; isolation:isolate; overflow:hidden; padding:clamp(1.7rem,4vw,3.4rem); border:1px solid rgba(103,235,215,.24); border-radius:30px; background:linear-gradient(112deg,rgba(15,43,61,.98),rgba(10,20,34,.98) 60%,rgba(13,31,49,.97)); margin:.25rem 0 1.8rem; box-shadow:0 28px 80px rgba(0,0,0,.27); }
.hero:before { content:""; position:absolute; z-index:-1; width:330px; height:330px; right:-95px; top:-145px; border-radius:50%; border:1px solid rgba(103,235,215,.16); box-shadow:0 0 0 28px rgba(103,235,215,.025),0 0 0 62px rgba(103,235,215,.02),0 0 0 100px rgba(103,235,215,.014); }
.hero:after { content:""; position:absolute; z-index:-1; width:180px; height:180px; right:8%; bottom:-150px; border-radius:50%; background:rgba(68,204,193,.12); filter:blur(20px); }
.eyebrow { color:#75ecd9; letter-spacing:.2em; text-transform:uppercase; font-size:.7rem; font-weight:800; }
.hero h1 { font-family:'Space Grotesk',sans-serif; font-size:clamp(2.6rem,6vw,4.6rem); line-height:1; letter-spacing:-.055em; margin:.9rem 0 1rem; color:#f5f8ff; }
.hero p { color:#c0d0df; font-size:1.06rem; line-height:1.8; max-width:700px; margin-bottom:1.25rem; }
.pill { display:inline-flex; align-items:center; padding:.45rem .8rem; border:1px solid #31546a; border-radius:999px; color:#d3e4ed; font-size:.76rem; margin:.3rem .35rem 0 0; background:rgba(6,16,27,.5); }
.panel { padding:1.35rem 1.4rem; border-radius:20px; background:linear-gradient(145deg,rgba(17,34,53,.96),rgba(10,21,35,.94)); border:1px solid #243c52; height:100%; box-shadow:0 12px 32px rgba(0,0,0,.13); transition:border-color .2s,transform .2s,box-shadow .2s; }
.panel:hover { border-color:#386b7c; box-shadow:0 16px 38px rgba(0,0,0,.2); }
.muted,[data-testid="stCaptionContainer"] { color:#9db1c5; font-size:.9rem; }
h1,h2,h3,h4 { font-family:'Space Grotesk',sans-serif !important; letter-spacing:-.03em; }
h2,h3 { color:#f1f6ff; }
p { line-height:1.7; }
[data-testid="stMetric"] { background:linear-gradient(145deg,rgba(19,41,61,.98),rgba(11,24,39,.98)); border:1px solid #2b4a60; padding:1rem 1.1rem; border-radius:17px; }
[data-testid="stMetricLabel"] { color:#a8bfd1; }
[data-testid="stMetricValue"] { color:#77ead7; font-family:'Space Grotesk',sans-serif; }
.stTextInput input { background:#0a1522 !important; border:1px solid #2b4358 !important; border-radius:13px !important; min-height:3.25rem; color:#f3f7ff !important; }
.stTextInput input:focus { border-color:#6ce6d1 !important; box-shadow:0 0 0 1px #6ce6d1 !important; }
.stButton button,.stFormSubmitButton button { border-radius:13px; font-weight:750; min-height:3rem; transition:all .18s ease; }
.stButton button[kind="primary"],.stFormSubmitButton button[kind="primary"] { background:linear-gradient(100deg,#62dfca,#9af3dc); color:#07151d; border:0; box-shadow:0 5px 18px rgba(87,221,200,.08); }
.stButton button[kind="primary"]:hover,.stFormSubmitButton button[kind="primary"]:hover { filter:brightness(1.07); box-shadow:0 8px 26px rgba(87,221,200,.2); transform:translateY(-1px); }
[data-testid="stExpander"] { border:1px solid #23394d; border-radius:15px; background:rgba(10,21,34,.7); overflow:hidden; }
[data-testid="stDataFrame"] { border:1px solid #20364d; border-radius:12px; overflow:hidden; }
hr { border-color:#20354a; }
a { color:#79ead8 !important; }
footer { visibility:hidden; }
@media(max-width:800px) { .block-container { padding:.75rem .85rem 2.5rem; } .hero { border-radius:22px; padding:1.5rem; } .hero h1 { font-size:clamp(2.4rem,11vw,3.4rem); } .hero p { font-size:.98rem; } .pill { font-size:.7rem; } }
</style>
<div class="hero">
  <div class="eyebrow">Threat awareness · URL intelligence</div>
  <h1>PhishShield</h1>
  <p>Inspect suspicious URLs, understand the warning signs, and make more informed decisions before opening a link. PhishShield analyzes URL text without visiting the destination.</p>
  <span class="pill">◈ Explainable signals</span><span class="pill">⌁ URL stays unvisited</span><span class="pill">✳ Supervised ML pipeline</span>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## 🛡️ PhishShield")
    st.caption("URL THREAT ANALYSIS")
    st.markdown("---")
    st.markdown("**What this tool checks**")
    st.write("URL structure, hostname patterns, suspicious words, shortening services, and other simple signals.")
    st.markdown("---")
    st.markdown("**Privacy by design**")
    st.write("The submitted URL is parsed as text. This app does not visit it, follow redirects, or fetch webpage content.")
    st.markdown("---")
    st.caption("A low score is not a safety guarantee.")
    st.markdown("---")
    st.markdown("**Project resources**")
    st.markdown("[GitHub repository](https://github.com/abhinavprasadsingh/PhishShield)")
    st.markdown("[Evaluation methodology](https://github.com/abhinavprasadsingh/PhishShield/blob/main/reports/evaluation.md)")
    st.markdown("[Viva / technical notes](https://github.com/abhinavprasadsingh/PhishShield/blob/main/docs/VIVA.md)")

st.markdown("### 🔍 Inspect a link")
st.write("Paste a URL to inspect its structure. Do not include private tokens, session IDs, or personal information.")
with st.form("url_analysis_form", clear_on_submit=False):
    url_input = st.text_input("URL to inspect", placeholder="https://example.com/account", help="You can include or omit https://")
    submitted = st.form_submit_button("Analyze URL  →", type="primary", use_container_width=True)

if submitted:
    try:
        normalized = normalize_url(url_input)
        features = extract_features(normalized)
        model = load_model()
        # Session-only scan history: it is cleared when this Streamlit session ends.
        if "scan_history" not in st.session_state:
            st.session_state.scan_history = []
        _, history_score, history_reasons = heuristic_assessment(features)
        history_record = {
            "Scanned at (UTC)": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "URL": normalized,
            "Hostname": urlparse(normalized).hostname or "",
            "Rule signal score": history_score,
            "Warning signals": "; ".join(history_reasons),
        }
        st.session_state.scan_history.append(history_record)
        st.session_state.scan_history = st.session_state.scan_history[-200:]
        st.markdown("---")
        st.markdown("### Assessment")
        if model is not None:
            try:
                import pandas as pd
                row = pd.DataFrame([[features[name] for name in FEATURES]], columns=FEATURES)
                pred = int(model.predict(row)[0])
                probabilities = model.predict_proba(row)[0] if hasattr(model, "predict_proba") else None
                # For binary classifiers, confidence is the predicted-class probability, not a safety score.
                confidence = float(max(probabilities)) if probabilities is not None else None
                label = "Potential phishing" if pred == 1 else "Model classifies as likely legitimate"
                left, right = st.columns([2, 1])
                with left:
                    st.subheader(label)
                    st.write("This result comes from the locally saved supervised model. Review the limitations and verify the domain independently.")
                with right:
                    if confidence is not None:
                        st.metric("Model confidence", f"{confidence:.0%}")
                    else:
                        st.metric("Model output", str(pred))
                st.info("Model confidence is not the probability that a URL is safe. A model can be wrong, especially on unfamiliar URLs.")
                # Show model-level feature importance when the estimator exposes it.
                estimator = model
                if hasattr(estimator, "named_steps"):
                    estimator = estimator.named_steps.get("model", estimator)
                importance = getattr(estimator, "feature_importances_", None)
                if importance is None and hasattr(estimator, "coef_"):
                    try:
                        importance = abs(estimator.coef_[0])
                    except (IndexError, TypeError):
                        importance = None
                if importance is not None and len(importance) == len(FEATURES):
                    import pandas as pd
                    importance_rows = sorted(
                        [{"Feature": name.replace("_", " ").title(), "Importance": float(value)}
                         for name, value in zip(FEATURES, importance)],
                        key=lambda item: item["Importance"], reverse=True
                    )
                    with st.expander("🧠 Model-level feature importance"):
                        st.caption("These values describe the fitted model overall; they do not explain this individual prediction or prove malicious intent.")
                        st.bar_chart(pd.DataFrame(importance_rows[:8]).set_index("Feature"))

            except Exception as exc:
                st.warning("The saved model could not be used with the expected feature schema. Showing heuristic demo mode instead.")
                label, score, reasons = heuristic_assessment(features)
                model = None
        if model is None:
            label, score, reasons = heuristic_assessment(features)
            left, right = st.columns([2, 1])
            with left:
                st.subheader(label)
                st.write("**Heuristic demo mode** — these are simple URL-pattern checks, not a trained ML prediction.")
                st.markdown("**Signals to review**")
                for reason in reasons:
                    st.markdown(f"- {reason}")
            with right:
                st.metric("Heuristic signal score", f"{score}/100", help="A rule-based indicator only; not a calibrated probability.")
                st.progress(score / 100)
                st.caption("Higher means more listed patterns matched, not a measured probability of fraud.")
        # Keep transparent rule-based indicators separate from any trained-model output.
        _, rule_score, rule_reasons = heuristic_assessment(features)
        with st.expander("🧭 URL warning signals to review", expanded=True):
            if rule_reasons and rule_reasons != ["No simple warning patterns were detected. This does not prove the site is safe."]:
                for reason in rule_reasons:
                    st.markdown(f"- {reason}")
            else:
                st.write("No simple warning patterns were detected. This does not prove the URL is safe.")
            st.caption(f"Rule-based indicator score: {rule_score}/100. This is not a probability and is not the trained model's explanation.")
        with st.expander("🧬 Explore extracted URL features"):
            rows = [{"Feature": key.replace("_", " ").title(), "Value": str(value)} for key, value in features.items()]
            st.dataframe(rows, hide_index=True, use_container_width=True)
        with st.expander("🧭 Safe next steps"):
            st.markdown("- Check the registered domain carefully, not just the brand name in the URL.")
            st.markdown("- Reach important services through a bookmark or by typing their known address yourself.")
            st.markdown("- Never enter passwords or one-time codes after following an unexpected message link.")
            st.markdown("- If in doubt, ask the organization through a separate, trusted channel.")
        with st.expander("ℹ️ Methodology, limitations & project links"):
            st.write("The app parses the URL string locally. It does not request the destination, follow redirects, inspect page content, or verify domain reputation. URL patterns can produce false positives and false negatives.")
            st.markdown("- [GitHub source code](https://github.com/abhinavprasadsingh/PhishShield)")
            st.markdown("- [Model evaluation methodology](https://github.com/abhinavprasadsingh/PhishShield/blob/main/reports/evaluation.md)")
            st.markdown("- [Technical notes / viva preparation](https://github.com/abhinavprasadsingh/PhishShield/blob/main/docs/VIVA.md)")
            st.caption("Evaluation metrics are only available after training and testing on a documented labeled dataset. No metrics are claimed by this demo.")
    except ValueError as exc:
        st.error(str(exc))
else:
    st.markdown("""
    <div class="panel">
      <h4>Ready when you are</h4>
      <p class="muted">Enter a URL above and select Analyze URL to see a structured assessment. No URL is checked until you submit the form.</p>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("#### What you'll get")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown('<div class="panel"><h4>🔎 Clear signals</h4><p class="muted">Understand which URL patterns triggered caution, without a black-box verdict.</p></div>', unsafe_allow_html=True)
    with c2:
        st.markdown('<div class="panel"><h4>🧬 Feature breakdown</h4><p class="muted">Explore hostname, length, protocol, and other structural indicators.</p></div>', unsafe_allow_html=True)
    with c3:
        st.markdown('<div class="panel"><h4>🔐 Privacy-minded</h4><p class="muted">The app analyzes text only and never opens the destination URL.</p></div>', unsafe_allow_html=True)


st.markdown("---")
st.markdown("## 🧰 Security workspace")
st.caption("Additional tools for batch checks, domain structure, scan history, and model evaluation.")

tool_tabs = st.tabs(["📄 Bulk scanner", "🌐 Domain intelligence", "🕘 History & analytics", "📊 Model dashboard"])

with tool_tabs[0]:
    st.markdown("### Analyze a CSV of URLs")
    st.write("Upload a CSV with a column named url. URLs are parsed locally; the app does not open them.")
    bulk_file = st.file_uploader("Choose CSV file", type=["csv"], key="phishshield_bulk_csv")
    if bulk_file is not None:
        try:
            import pandas as pd
            bulk_df = pd.read_csv(bulk_file)
            if "url" not in bulk_df.columns:
                st.error("Your CSV needs a column named url.")
            elif len(bulk_df) > 1000:
                st.error("For this demo, upload at most 1,000 URLs per file.")
            else:
                bulk_model = load_model()
                batch_rows = []
                for raw_url in bulk_df["url"].fillna("").astype(str):
                    try:
                        clean_url = normalize_url(raw_url)
                        feat = extract_features(clean_url)
                        _, rule_score, reasons = heuristic_assessment(feat)
                        prediction = "Heuristic only (no model file)"
                        model_confidence = None
                        if bulk_model is not None:
                            import pandas as pd
                            model_row = pd.DataFrame([[feat[name] for name in FEATURES]], columns=FEATURES)
                            pred_value = int(bulk_model.predict(model_row)[0])
                            prediction = "Potential phishing" if pred_value == 1 else "Likely legitimate (model class)"
                            if hasattr(bulk_model, "predict_proba"):
                                probs = bulk_model.predict_proba(model_row)[0]
                                model_confidence = float(max(probs))
                        batch_rows.append({
                            "Input URL": raw_url,
                            "Normalized URL": clean_url,
                            "Model result": prediction,
                            "Model confidence (not safety probability)": "" if model_confidence is None else round(model_confidence, 4),
                            "Rule signal score (0-100)": rule_score,
                            "Warning signals": "; ".join(reasons),
                            "Validation": "OK",
                        })
                    except ValueError as exc:
                        batch_rows.append({
                            "Input URL": raw_url,
                            "Normalized URL": "",
                            "Model result": "Not analyzed",
                            "Model confidence (not safety probability)": "",
                            "Rule signal score (0-100)": "",
                            "Warning signals": "",
                            "Validation": str(exc),
                        })
                result_df = pd.DataFrame(batch_rows)
                st.dataframe(result_df, hide_index=True, use_container_width=True)
                st.download_button(
                    "⬇️ Download scan report (CSV)",
                    data=sanitize_csv_for_spreadsheet(result_df).to_csv(index=False).encode("utf-8"),
                    file_name="phishshield_bulk_scan.csv",
                    mime="text/csv",
                    use_container_width=True,
                )
                st.caption("Rule scores are transparent indicators, not calibrated probabilities. Model confidence is not a guarantee of safety.")
        except Exception as exc:
            st.error(f"Could not read this CSV: {exc}")

with tool_tabs[1]:
    st.markdown("### Domain intelligence (offline URL parsing)")
    st.write("This section describes URL structure only. It does not perform DNS, WHOIS, certificate, reputation, or domain-age lookups.")
    intel_input = st.text_input("URL for domain breakdown", placeholder="https://login.example.com/account", key="phishshield_domain_input")
    if st.button("Inspect domain structure", key="phishshield_domain_button", type="primary"):
        try:
            intel_url = normalize_url(intel_input)
            intel_parsed = urlparse(intel_url)
            intel_host = (intel_parsed.hostname or "").lower().rstrip(".")
            try:
                ipaddress.ip_address(intel_host.strip("[]"))
                host_kind = "IP address"
            except ValueError:
                host_kind = "Domain hostname"
            labels = [part for part in intel_host.split(".") if part]
            root_hint = ".".join(labels[-2:]) if len(labels) >= 2 else intel_host
            d1, d2, d3 = st.columns(3)
            d1.metric("Scheme", intel_parsed.scheme.upper())
            d2.metric("Hostname type", host_kind)
            d3.metric("Subdomain labels", max(0, len(labels) - 2))
            st.markdown("**Parsed details**")
            st.dataframe([
                {"Property": "Hostname", "Value": intel_host},
                {"Property": "Approximate last two labels (not always registrable domain)", "Value": root_hint},
                {"Property": "Port", "Value": str(intel_parsed.port or "Default / not specified")},
                {"Property": "Path length", "Value": str(len(intel_parsed.path))},
                {"Property": "Query present", "Value": "Yes" if intel_parsed.query else "No"},
                {"Property": "HTTPS used", "Value": "Yes" if intel_parsed.scheme == "https" else "No"},
            ], hide_index=True, use_container_width=True)
            st.info("HTTPS encrypts a connection but does not prove the site is legitimate. The last-two-label hint can be wrong for domains such as co.uk.")
        except ValueError as exc:
            st.error(str(exc))

with tool_tabs[2]:
    st.markdown("### Session scan history")
    st.caption("History is stored only in this active Streamlit session and is not written to a database.")
    history = st.session_state.get("scan_history", [])
    if history:
        import pandas as pd
        history_df = pd.DataFrame(history)
        h1, h2, h3 = st.columns(3)
        h1.metric("Scans this session", len(history_df))
        h2.metric("Unique hostnames", history_df["Hostname"].nunique())
        h3.metric("High rule signals (45+)", int((pd.to_numeric(history_df["Rule signal score"], errors="coerce") >= 45).sum()))
        st.dataframe(history_df.iloc[::-1], hide_index=True, use_container_width=True)
        st.download_button("⬇️ Export session history", sanitize_csv_for_spreadsheet(history_df).to_csv(index=False).encode("utf-8"), "phishshield_session_history.csv", "text/csv")
        if st.button("Clear session history", key="phishshield_clear_history"):
            st.session_state.scan_history = []
            st.rerun()
    else:
        st.info("Analyze a URL above or use the bulk scanner to begin reviewing results. Single-URL scans appear here.")

with tool_tabs[3]:
    st.markdown("### Documented model evaluation")
    st.write("These are the repository's recorded held-out dataset results, not a live measurement of whichever model file is currently loaded by this app.")
    st.caption("Dataset: UCI PhiUSIIL Phishing URL dataset. The evaluation report notes approximate domain grouping and model selection on the test split; use caution when interpreting these results.")
    import pandas as pd
    metrics_df = pd.DataFrame([
        {"Model": "HistGradientBoosting", "Accuracy": 0.997, "Precision": 0.999, "Recall": 0.994, "F1": 0.996, "Average precision": 0.999},
        {"Model": "Random Forest", "Accuracy": 0.997, "Precision": 0.998, "Recall": 0.994, "F1": 0.996, "Average precision": 0.998},
        {"Model": "Logistic Regression", "Accuracy": 0.995, "Precision": 0.999, "Recall": 0.989, "F1": 0.994, "Average precision": 0.998},
    ])
    st.dataframe(metrics_df.style.format({col: "{:.1%}" for col in ["Accuracy", "Precision", "Recall", "F1", "Average precision"]}), hide_index=True, use_container_width=True)
    st.bar_chart(metrics_df.set_index("Model")[["Precision", "Recall", "F1", "Average precision"]])
    st.markdown("**Selected model confusion matrix**")
    st.dataframe(pd.DataFrame([[26759, 19], [125, 20225]], index=["Actual legitimate", "Actual phishing"], columns=["Predicted legitimate", "Predicted phishing"]), use_container_width=True)
    st.caption("The model artifact is not committed to the repository by default, so these documented metrics do not confirm that the live app is currently running the trained model. See reports/evaluation.md for methodology and limitations.")

st.markdown("---")
st.markdown('<p class="muted">PhishShield is an educational awareness project, not a guarantee of safety or a replacement for browser protection and professional security tools.</p>', unsafe_allow_html=True)
