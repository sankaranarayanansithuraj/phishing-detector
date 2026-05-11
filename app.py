import streamlit as st
import pickle
import pandas as pd
from pathlib import Path
from utils.preprocessor import clean_text
from utils.ioc_extractor import extract_iocs
from utils.severity_engine import calculate_severity
from utils.response_engine import get_response_plan
from explainer import get_explanation

st.set_page_config(
    page_title="Phishing Incident Response System",
    page_icon="🛡️",
    layout="wide"
)

BASE_DIR = Path(__file__).resolve().parent

@st.cache_resource
def load_model():
    with open(BASE_DIR / 'models' / 'phishing_model.pkl', 'rb') as f:
        model = pickle.load(f)
    with open(BASE_DIR / 'models' / 'vectorizer.pkl', 'rb') as f:
        vectorizer = pickle.load(f)
    return model, vectorizer

# ── Header ─────────────────────────────────────────────────────────────────
st.title("🛡️ AI-Assisted Phishing Incident Response System")
st.markdown("Paste a suspicious email or message below. The system will detect, classify, and recommend actions.")
st.divider()

# ── Load model ─────────────────────────────────────────────────────────────
try:
    model, vectorizer = load_model()
    model_ready = True
except FileNotFoundError:
    st.error("⚠️ Model not found. Please run `python train_model.py` first in your terminal.")
    model_ready = False
    st.stop()

# ── Input ──────────────────────────────────────────────────────────────────
message = st.text_area(
    "📨 Paste message or email content here:",
    height=220,
    placeholder="Example: Dear user, your account has been suspended. Click here to verify immediately: http://secure-login-update.com/verify"
)

col_btn, col_clear = st.columns([1, 5])
with col_btn:
    analyze = st.button("🔍 Analyze", type="primary", disabled=not model_ready)
with col_clear:
    clear = st.button("🗑️ Clear")

if clear:
    st.rerun()

# ── Analysis ───────────────────────────────────────────────────────────────
if analyze and message.strip():
    with st.spinner("Analyzing message..."):

        # Step 1: Preprocess
        cleaned = clean_text(message)

        # Step 2: Vectorize
        vec = vectorizer.transform([cleaned])

        # Step 3: Predict
        pred = model.predict(vec)[0]

        # Step 4: Get phishing probability (handles both string and int labels)
        classes     = list(model.classes_)
        phish_index = next(
            (i for i, c in enumerate(classes) if 'phish' in str(c).lower()),
            1
        )
        proba = model.predict_proba(vec)[0][phish_index]

        # Step 5: Check if phishing (handles 'Phishing Email' or 1)
        is_phishing = (pred == 1) or ('phish' in str(pred).lower())

        # Step 6: Extract IoCs
        iocs = extract_iocs(message)

        # Step 7: Severity
        severity, score = calculate_severity(proba, iocs)

        # Step 8: Response plan
        response = get_response_plan(severity)

        # Step 9: Explainability
        explain = get_explanation(cleaned)

    # ── Row 1: Summary ─────────────────────────────────────────────────────
    st.subheader("📊 Detection Summary")
    m1, m2, m3, m4 = st.columns(4)

    with m1:
        if is_phishing:
            st.error("⚠️ PHISHING DETECTED")
        else:
            st.success("✅ LOOKS LEGITIMATE")

    with m2:
        st.metric(
            "Model Confidence",
            f"{proba * 100:.1f}%",
            help="How confident the AI is that this is phishing"
        )

    with m3:
        color_map = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}
        st.metric("Severity Level", f"{color_map[severity]} {severity}")

    with m4:
        st.metric("Risk Score", f"{score} / 100")

    st.divider()

    # ── Row 2: IoCs ────────────────────────────────────────────────────────
    st.subheader("🔎 Indicators of Compromise (IoCs)")
    c1, c2 = st.columns(2)

    with c1:
        if iocs['suspicious_keywords']:
            st.error(f"**Suspicious keywords found ({len(iocs['suspicious_keywords'])}):**")
            for kw in iocs['suspicious_keywords']:
                st.write(f"  • `{kw}`")
        else:
            st.success("No suspicious keywords detected")

        if iocs['ip_addresses']:
            st.warning(f"**IP addresses found:** {', '.join(iocs['ip_addresses'])}")

    with c2:
        if iocs['urls']:
            st.warning(f"**URLs found ({len(iocs['urls'])}):**")
            for url in iocs['urls'][:5]:
                st.code(url)
        if iocs['suspicious_urls']:
            st.error(f"**Suspicious URL flags ({len(iocs['suspicious_urls'])}):**")
            for item in iocs['suspicious_urls']:
                st.write(f"  • `{item['url'][:60]}` → {', '.join(item['flags'])}")
        if iocs['emails']:
            st.info(f"**Email addresses:** {', '.join(iocs['emails'])}")
        if not iocs['urls'] and not iocs['emails'] and not iocs['suspicious_urls']:
            st.success("No malicious URLs or emails detected")

    st.divider()

    # ── Row 3: Response Plan ───────────────────────────────────────────────
    st.subheader(f"{response['color']} Recommended Response Plan — {severity} Severity")
    st.info(f"**Urgency:** {response['urgency']}")
    st.caption(response['description'])

    for action in response['actions']:
        st.write(action)

    st.divider()

    # ── Row 4: Explainability ──────────────────────────────────────────────
    st.subheader("🧠 Why did the AI decide this? (Explainability)")
    st.caption("SHAP values show which words pushed the model toward Phishing or Legitimate.")

    if explain:
        exp_df = pd.DataFrame(explain, columns=['Word / Phrase', 'SHAP Value'])
        exp_df['Direction'] = exp_df['SHAP Value'].apply(
            lambda x: '🔴 Towards Phishing' if x > 0 else '🟢 Towards Legitimate'
        )
        exp_df['Strength'] = exp_df['SHAP Value'].abs().round(4)
        exp_df = exp_df[['Word / Phrase', 'Strength', 'Direction']].sort_values(
            'Strength', ascending=False
        )
        st.dataframe(exp_df, use_container_width=True, hide_index=True)
    else:
        st.info("No strong individual word features found for this message.")

elif analyze and not message.strip():
    st.warning("Please paste a message before clicking Analyze.")