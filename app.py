import os
import tempfile
import streamlit as st

from core.transcriber import Transcriber
from core.ensemble import predict_ensemble
from core.signal_detector import SignalDetector
from core.summarizer import Summarizer


st.set_page_config(page_title="Scam Detector", page_icon="🛡️", layout="wide")


@st.cache_resource(show_spinner=False)
def load_components():
    return Transcriber(), SignalDetector(), Summarizer()


transcriber, signal_detector, summarizer = load_components()


def build_result(transcript: str) -> dict:
    if not transcript or not transcript.strip():
        raise ValueError("Please provide some text or upload a supported file.")

    ensemble_res = predict_ensemble(transcript)
    scam_score = float(ensemble_res["final_score"])
    language = ensemble_res["language"]

    signals_res = signal_detector.detect_signals(transcript)
    signals_triggered = sum(1 for signal in signals_res.values() if signal["triggered"])
    summary = summarizer.generate_summary(transcript)

    if scam_score >= 0.75:
        verdict = "SCAM"
        confidence_band = "HIGH"
    elif scam_score >= 0.48:
        verdict = "SUSPICIOUS"
        confidence_band = "MEDIUM"
    else:
        verdict = "SAFE"
        confidence_band = "LOW"

    return {
        "transcript": transcript,
        "scam_score": round(scam_score, 2),
        "verdict": verdict,
        "confidence_band": confidence_band,
        "signals": signals_res,
        "signals_triggered": signals_triggered,
        "summary": summary,
        "language": language,
    }


def analyze_uploaded_file(uploaded_file) -> dict:
    if uploaded_file is None:
        raise ValueError("No file was uploaded.")

    suffix = os.path.splitext(uploaded_file.name)[1] if uploaded_file.name else ""
    temp_fd, temp_path = tempfile.mkstemp(suffix=suffix)
    os.close(temp_fd)

    try:
        with open(temp_path, "wb") as handle:
            handle.write(uploaded_file.getbuffer())

        mime_type = uploaded_file.type or "application/octet-stream"
        transcript = transcriber.transcribe(temp_path, mime_type)
        return build_result(transcript)
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


st.title("🛡️ Scam Detector")
st.caption("Upload a file or paste a conversation to get a scam risk verdict from the existing ML pipeline.")

with st.sidebar:
    st.header("How it works")
    st.write("This app reuses the same model pipeline as the project core modules for:")
    st.markdown("- text transcription / OCR")
    st.markdown("- ensemble scam scoring")
    st.markdown("- signal detection")
    st.markdown("- summary generation")
    st.info("First launch may take a few minutes because the models are being loaded.")

input_mode = st.radio("Choose input mode", ["Text", "Upload file"], horizontal=True)

if input_mode == "Text":
    text_input = st.text_area(
        "Paste transcript or conversation text",
        height=220,
        placeholder="Example: Your Aadhaar is blocked, pay now to avoid arrest...",
    )

    if st.button("Analyze text", use_container_width=True):
        if not text_input.strip():
            st.warning("Please enter some text first.")
        else:
            with st.spinner("Analyzing the conversation..."):
                try:
                    result = build_result(text_input)
                    st.session_state["result"] = result
                except Exception as exc:  # pragma: no cover - UI error handling
                    st.error(f"Analysis failed: {exc}")
else:
    uploaded_file = st.file_uploader(
        "Upload a text, audio, video, or image file",
        type=["txt", "wav", "mp3", "m4a", "flac", "ogg", "aac", "mp4", "mkv", "avi", "mov", "png", "jpg", "jpeg", "bmp", "tiff", "webp"],
    )

    if st.button("Analyze uploaded file", use_container_width=True):
        if uploaded_file is None:
            st.warning("Please choose a file first.")
        else:
            with st.spinner("Processing the uploaded file..."):
                try:
                    result = analyze_uploaded_file(uploaded_file)
                    st.session_state["result"] = result
                except Exception as exc:  # pragma: no cover - UI error handling
                    st.error(f"File analysis failed: {exc}")

if "result" in st.session_state:
    result = st.session_state["result"]

    st.success("Analysis complete")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Verdict", result["verdict"])
    col2.metric("Risk Score", f"{result['scam_score']:.2f}")
    col3.metric("Confidence", result["confidence_band"])
    col4.metric("Signals Triggered", result["signals_triggered"])

    st.subheader("Summary")
    st.write(result["summary"])

    st.subheader("Detected language")
    st.write(result["language"])

    st.subheader("Transcript")
    st.text_area("Processed transcript", result["transcript"], height=180)

    st.subheader("Signal breakdown")
    signal_items = list(result["signals"].items())
    for key, payload in signal_items:
        with st.expander(f"{key.replace('_', ' ').title()} - {'triggered' if payload['triggered'] else 'not triggered'}"):
            st.write(f"Score: {payload['score']:.2f}")
            st.write(f"Triggered: {payload['triggered']}")
            if payload["phrases_caught"]:
                st.write("Phrases caught: " + ", ".join(payload["phrases_caught"]))
            else:
                st.write("Phrases caught: none")
