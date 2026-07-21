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
    Reused for both classification and extractive summarization.
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
    Lazily loads and returns the cardiffnlp/twitter-xlm-roberta-base sequence classification pipeline.
    Identifies hostile, urgent, or manipulative intent.
    """
    global _xlm_pipeline
    if _xlm_pipeline is None:
        logger.info("Initializing cardiffnlp/twitter-xlm-roberta-base on CPU...")
        from transformers import pipeline
        _xlm_pipeline = pipeline(
            "text-classification",
            model="cardiffnlp/twitter-xlm-roberta-base",
            device=-1
        )
        logger.info("XLM-RoBERTa text classifier successfully loaded.")
    return _xlm_pipeline


def _train_and_save_fallback_xgb() -> Tuple[Any, Any]:
    """
    Trains a baseline TF-IDF + XGBoost model on synthetic scam detection patterns,
    saving them to disk so they can be loaded cleanly on startup/subsequent runs.
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

    # Save models to disk
    vectorizer_path = os.path.join(MODELS_DIR, "tfidf_vectorizer.pkl")
    model_path = os.path.join(MODELS_DIR, "xgb_model.json")

    with open(vectorizer_path, "wb") as f:
        pickle.dump(vectorizer, f)
    xgb_clf.save_model(model_path)

    logger.info(f"Successfully trained and saved fallback models to: {MODELS_DIR}")
    return vectorizer, xgb_clf


def get_xgb_components() -> Tuple[Any, Any]:
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

    return _tfidf_vectorizer, _xgb_model  # ← this line was missing

def detect_language_safely(text: str) -> str:
    """
    Helper function to safely detect the main language of the text input.
    Supports Hindi, English, and Hinglish.
    """
    cleaned = text.strip()
    if not cleaned:
        return "English"
    
    try:
        lang = detect(cleaned)
        if lang == "hi":
            return "Hindi"
        
        # Simple Hinglish heuristic: check if classified as English but contains heavy Hindi terms
        hinglish_tokens = {"bhejo", "paise", "karo", "giraftari", "turant", "abhi", "kisi", "mat", "batao", "bolo"}
        words = set(cleaned.lower().split())
        if words.intersection(hinglish_tokens):
            return "Hinglish"
            
        if lang == "en":
            return "English"
        return f"Multilingual ({lang})"
    except Exception:
        # Fallback to English if detector fails
        return "English"


def predict_ensemble(text: str) -> Dict[str, Any]:
    """
    Evaluates transcript text across the three model ensemble layers.
    Calculates final scam score using standard weighted formula:
    final_score = (bart_score * 0.40) + (xlm_score * 0.35) + (xgb_score * 0.25)
    """
    cleaned_text = text.strip()
    if not cleaned_text:
        return {
            "final_score": 0.0,
            "bart_score": 0.0,
            "xlm_score": 0.0,
            "xgb_score": 0.0,
            "language": "English"
        }

    # 1. BART Zero-shot scoring
    logger.info("Running BART Zero-Shot inference...")
    bart = get_bart_pipeline()
    candidate_labels = ["fraudulent scam activity", "safe legitimate request"]
    bart_res = bart(cleaned_text, candidate_labels=candidate_labels)
    # Map label scores
    label_mapping = dict(zip(bart_res["labels"], bart_res["scores"]))
    bart_score = float(label_mapping.get("fraudulent scam activity", 0.0))

    # 2. XLM-RoBERTa Intent / Tone analysis
    logger.info("Running XLM-RoBERTa classification...")
    xlm = get_xlm_pipeline()
    # Handle maximum length truncation to prevent crash
    truncated_text = cleaned_text[:512]
    xlm_res = xlm(truncated_text)
    
    # RoBERTa output classification scoring logic:
    # If the classifier returns non-standard/neutral output, we can evaluate model confidence.
    # Safe fallback: we scale the text-classification score based on intent keywords or return raw confidence.
    xlm_score_raw = float(xlm_res[0]["score"])
    xlm_label = xlm_res[0]["label"].upper()
    
    # Map negative/aggressive/unusual classification outputs as higher risk indicators.
    if "NEGATIVE" in xlm_label or "LABEL_0" in xlm_label or "LABEL_1" in xlm_label:
        # Standardize score safely
        xlm_score = xlm_score_raw
    else:
        # If categorized as clean/positive sentiment, reduce model scam score contribution
        xlm_score = max(0.0, 1.0 - xlm_score_raw)

    # 3. XGBoost + TF-IDF model inference
    logger.info("Running XGBoost model inference...")
    vectorizer, xgb_model = get_xgb_components()
    logger.info(f"Vectorizer: {_tfidf_vectorizer}")
    logger.info(f"XGB Model: {_xgb_model}")
    text_vectorized = vectorizer.transform([cleaned_text])
    xgb_probs = xgb_model.predict_proba(text_vectorized)
    # Probability of class 1 (scam)
    xgb_score = float(xgb_probs[0][1])

    # 4. Calculate final weighted score
    final_score = (bart_score * 0.40) + (xlm_score * 0.35) + (xgb_score * 0.25)
    
    # Clamp bounds safely
    final_score = max(0.0, min(1.0, final_score))
    
    detected_lang = detect_language_safely(cleaned_text)

    logger.info(
        f"Ensemble execution complete. Scores - BART: {bart_score:.4f}, "
        f"XLM: {xlm_score:.4f}, XGB: {xgb_score:.4f}. Final Score: {final_score:.4f}"
    )

    return {
        "final_score": final_score,
        "bart_score": bart_score,
        "xlm_score": xlm_score,
        "xgb_score": xgb_score,
        "language": detected_lang
    }