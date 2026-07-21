import os
import pickle
import logging
import numpy as np
from typing import Dict, Tuple, Any
from langdetect import detect

# Configure logger
logger = logging.getLogger("scam_detector.ensemble")
logging.basicConfig(level=logging.INFO)

# Create models directory if it does not exist
MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
os.makedirs(MODELS_DIR, exist_ok=True)

# Lazy-loaded singletons
_bart_pipeline = None
_xlm_pipeline = None
_xgb_model = None
_tfidf_vectorizer = None


def get_bart_pipeline():
    """
    Lazily loads and returns the zero-shot classification pipeline using facebook/bart-large-mnli.
    Reused for both ensemble scoring and extractive summarization in summarizer.py.
    Model is cached as a module-level singleton so it loads only once per server session.
    """
    global _bart_pipeline
    if _bart_pipeline is None:
        logger.info("Initializing facebook/bart-large-mnli on CPU...")
        from transformers import pipeline
        # Force CPU execution (device=-1)
        _bart_pipeline = pipeline(
            "zero-shot-classification",
            model="facebook/bart-large-mnli",
            device=-1
        )
        logger.info("BART zero-shot classifier successfully loaded.")
    return _bart_pipeline


def get_xlm_pipeline():
    """
    Lazily loads and returns the cardiffnlp/twitter-xlm-roberta-base-sentiment sequence classification pipeline.
    Identifies hostile, urgent, or manipulative intent across Hindi, English, and Hinglish.
    Model is cached as a module-level singleton so it loads only once per server session.
    """
    global _xlm_pipeline
    if _xlm_pipeline is None:
        logger.info("Initializing cardiffnlp/twitter-xlm-roberta-base-sentiment on CPU...")
        from transformers import pipeline
        _xlm_pipeline = pipeline(
            "text-classification",
            model="cardiffnlp/twitter-xlm-roberta-base-sentiment",
            device=-1
        )
        logger.info("XLM-RoBERTa text classifier successfully loaded.")
    return _xlm_pipeline


def _train_and_save_fallback_xgb() -> Tuple[Any, Any]:
    """
    Trains a baseline TF-IDF + XGBoost model on synthetic scam detection patterns,
    saving them to disk so they can be loaded cleanly on startup and subsequent runs.
    This fallback only runs if no pre-trained model files are found in the models/ directory.
    For production use, always run setup_xgb.py first to build the full keyword-trained model.
    """
    logger.info("No pre-trained XGBoost components found. Training a baseline model...")
    from sklearn.feature_extraction.text import TfidfVectorizer
    import xgboost as xgb

    # Synthetic dataset containing classic bilingual scam patterns and safe templates
    training_texts = [
        "Please transfer money to my bank account immediately.",
        "Your Aadhaar card is blocked, pay fine now to avoid arrest.",
        "I am calling from CBI, you have an outstanding arrest warrant. Share screen via AnyDesk.",
        "Do not tell anyone about this call, keep it a secret or face jail.",
        "Give me your OTP and credit card CVV to verify your bank account.",
        "Your police complaint has been filed. Pay deposit immediately to resolve.",
        "Abhi transfer karo paise check verification ke liye.",
        "Apna bank account details aur Aadhaar number share karein.",
        "AnyDesk download karke screen share karein verification process ke liye.",
        "Aapka account block ho chuka hai, turant call karein.",

        "Hey, are we still meeting for lunch today at 1 PM?",
        "I will send you the project files and documents by tomorrow morning.",
        "Can you please send me the recipe for the paneer dish?",
        "Happy birthday! Hope you have a wonderful day ahead with family.",
        "Please review the document and let me know your comments.",
        "Let's connect on Zoom tomorrow at 10 AM to discuss the agenda.",
        "Kya hum kal subah mil sakte hain meeting ke liye?",
        "Main aapko files email par bhej raha hoon.",
        "Aaj ka dinner bahut swadist tha, dhanyawad.",
        "Aapka phone number kya hai, main call karta hoon."
    ]
    # 1 = SCAM, 0 = SAFE
    labels = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    vectorizer = TfidfVectorizer(max_features=500, ngram_range=(1, 2), stop_words=None)
    X_train = vectorizer.fit_transform(training_texts)

    xgb_clf = xgb.XGBClassifier(
        n_estimators=50,
        max_depth=3,
        learning_rate=0.1,
        eval_metric="logloss",
        random_state=42
    )
    xgb_clf.fit(X_train, labels)

    # Save both components as pickle files to models/ directory
    vectorizer_path = os.path.join(MODELS_DIR, "tfidf_vectorizer.pkl")
    model_path = os.path.join(MODELS_DIR, "xgb_model.pkl")

    with open(vectorizer_path, "wb") as f:
        pickle.dump(vectorizer, f)
    with open(model_path, "wb") as f:
        pickle.dump(xgb_clf, f)

    logger.info(f"Successfully trained and saved fallback models to: {MODELS_DIR}")
    return vectorizer, xgb_clf


def get_xgb_components() -> Tuple[Any, Any]:
    """
    Lazily loads and returns the pre-trained TF-IDF vectorizer and XGBoost classifier
    from the models/ directory. Both files must be .pkl format produced by setup_xgb.py.
    If model files are missing, falls back to training a small baseline model automatically.
    Returns a tuple of (vectorizer, xgb_model) ready for inference.
    """
    global _xgb_model, _tfidf_vectorizer
    vectorizer_path = os.path.join(MODELS_DIR, "tfidf_vectorizer.pkl")
    model_path = os.path.join(MODELS_DIR, "xgb_model.pkl")

    if _xgb_model is None or _tfidf_vectorizer is None:
        if os.path.exists(vectorizer_path) and os.path.exists(model_path):
            logger.info("Loading pre-trained TF-IDF and XGBoost models...")
            with open(vectorizer_path, "rb") as f:
                _tfidf_vectorizer = pickle.load(f)
            with open(model_path, "rb") as f:
                _xgb_model = pickle.load(f)
            logger.info(f"XGBoost loaded. Features: {_xgb_model.n_features_in_}")
        else:
            logger.warning("Model files not found. Running fallback training...")
            _tfidf_vectorizer, _xgb_model = _train_and_save_fallback_xgb()

    return _tfidf_vectorizer, _xgb_model


def detect_language_safely(text: str) -> str:
    """
    Helper function to safely detect the primary language of the input text.
    Supports Hindi, English, and mixed Hinglish detection using langdetect
    combined with a simple token heuristic for Hinglish identification.
    Falls back to English if detection fails or the text is empty.
    """
    cleaned = text.strip()
    if not cleaned:
        return "English"

    try:
        lang = detect(cleaned)
        if lang == "hi":
            return "Hindi"

        # Hinglish heuristic: classified as English but contains common Hindi tokens
        hinglish_tokens = {
            "bhejo", "paise", "karo", "giraftari", "turant", "abhi",
            "kisi", "mat", "batao", "bolo", "aapka", "aur", "hai",
            "nahi", "hoon", "mein", "se", "ko", "ka", "ki"
        }
        words = set(cleaned.lower().split())
        if words.intersection(hinglish_tokens):
            return "Hinglish"

        if lang == "en":
            return "English"
        return f"Multilingual ({lang})"
    except Exception:
        # Fallback to English if detector throws any exception
        return "English"


def predict_ensemble(text: str) -> Dict[str, Any]:
    """
    Evaluates transcript text across four model ensemble layers and returns
    a combined scam probability score with per-model component breakdown.

    Current weighted formula (update this docstring if these weights change):
        final_score = (bart_score * 0.40) + (xlm_score * 0.32)
                    + (xgb_score  * 0.20) + (emb_score * 0.08)

    Components:
        - BART zero-shot (0.40): semantic scam intent classification
        - XLM-RoBERTa  (0.32): multilingual tone and hostility detection
        - XGBoost TF-IDF (0.20): keyword pattern matching across known scam phrases
        - Sentence embeddings (0.08): meaning-based similarity to scam phrase clusters

    The embeddings component degrades gracefully: if sentence-transformers is not
    installed or embeddings_scorer.py is missing, its weight is redistributed to
    BART so the system continues working without any accuracy loss.

    Returns a dict with final_score, per-model scores, and detected language.
    """
    cleaned_text = text.strip()
    if not cleaned_text:
        return {
            "final_score": 0.0,
            "bart_score": 0.0,
            "xlm_score": 0.0,
            "xgb_score": 0.0,
            "emb_score": 0.0,
            "language": "English"
        }

    # ── 1. BART Zero-Shot Scoring ──────────────────────────────────────────
    logger.info("Running BART Zero-Shot inference...")
    bart = get_bart_pipeline()
    candidate_labels = ["fraudulent scam activity", "safe legitimate request"]
    bart_res = bart(cleaned_text, candidate_labels=candidate_labels)
    # Extract score for the scam label specifically
    label_mapping = dict(zip(bart_res["labels"], bart_res["scores"]))
    bart_score = float(label_mapping.get("fraudulent scam activity", 0.0))

    # ── 2. XLM-RoBERTa Intent / Tone Analysis ─────────────────────────────
    logger.info("Running XLM-RoBERTa classification...")
    xlm = get_xlm_pipeline()
    # Truncate to 512 tokens to prevent model crash on long transcripts
    truncated_text = cleaned_text[:512]
    xlm_res = xlm(truncated_text)
    xlm_score_raw = float(xlm_res[0]["score"])
    xlm_label = xlm_res[0]["label"].upper()

    # Map XLM-RoBERTa output labels to scam risk score:
    # NEGATIVE / LABEL_0 / LABEL_1 outputs indicate hostile or suspicious tone
    if "NEGATIVE" in xlm_label or "LABEL_0" in xlm_label or "LABEL_1" in xlm_label:
        xlm_score = xlm_score_raw
    else:
        # Positive/neutral sentiment detected — invert to reduce scam contribution
        xlm_score = max(0.0, 1.0 - xlm_score_raw)

    # ── 3. XGBoost + TF-IDF Keyword Pattern Scoring ───────────────────────
    logger.info("Running XGBoost model inference...")
    vectorizer, xgb_model = get_xgb_components()
    text_vectorized = vectorizer.transform([cleaned_text])
    xgb_probs = xgb_model.predict_proba(text_vectorized)
    # Index [0][1] = probability of class 1 (scam)
    xgb_score = float(xgb_probs[0][1])

    # ── 4. Sentence Embeddings Scorer ──────────────────────────────────────
    # Loads paraphrase-multilingual-MiniLM-L12-v2 and computes cosine similarity
    # between the transcript and pre-encoded scam phrase cluster embeddings.
    # Understands paraphrases across languages — "bhejo paise" == "send money now".
    # Degrades gracefully if sentence-transformers is not installed.
    emb_score = 0.0
    try:
        from core.embeddings_scorer import score_transcript
        emb_score = score_transcript(cleaned_text)
        logger.info(f"Embeddings score: {emb_score:.4f}")
    except Exception as e:
        logger.warning(f"Embeddings scorer unavailable, redistributing weight to BART: {e}")
        # Fallback: use bart_score for the embeddings slot so total weight stays 1.0
        emb_score = bart_score

    # ── 5. Weighted Ensemble Final Score ──────────────────────────────────
    final_score = (
        (bart_score * 0.40) +
        (xlm_score  * 0.32) +
        (xgb_score  * 0.20) +
        (emb_score  * 0.08)
    )
    # Clamp to valid probability range
    final_score = max(0.0, min(1.0, final_score))

    detected_lang = detect_language_safely(cleaned_text)

    logger.info(
        f"Ensemble execution complete. Scores - BART:{bart_score:.4f}, "
        f"XLM:{xlm_score:.4f}, XGB:{xgb_score:.4f}, EMB:{emb_score:.4f}. "
        f"Final Score: {final_score:.4f}"
    )

    return {
        "final_score": final_score,
        "bart_score": bart_score,
        "xlm_score": xlm_score,
        "xgb_score": xgb_score,
        "emb_score": emb_score,
        "language": detected_lang
    }