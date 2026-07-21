import os
import json
import logging
import numpy as np

logger = logging.getLogger("scam_detector.embeddings")

CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config")
KEYWORDS_EN_PATH = os.path.join(CONFIG_DIR, "keywords_en.json")
KEYWORDS_HI_PATH = os.path.join(CONFIG_DIR, "keywords_hi.json")

_model = None
_scam_embeddings = None
_safe_embeddings = None


def get_embeddings_model():
    global _model
    if _model is None:
        logger.info("Loading paraphrase-multilingual-MiniLM-L12-v2...")
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer("paraphrase-multilingual-MiniLM-L12-v2")
        logger.info("MiniLM model loaded.")
    return _model


def _build_phrase_clusters():
    global _scam_embeddings, _safe_embeddings

    with open(KEYWORDS_EN_PATH, encoding="utf-8") as f:
        en = json.load(f)
    with open(KEYWORDS_HI_PATH, encoding="utf-8") as f:
        hi = json.load(f)

    scam_signals = ["demand", "urgency", "threat", "manipulation",
                    "share_screen", "personal_info", "fake_rewards"]

    scam_phrases = []
    for signal in scam_signals:
        scam_phrases.extend(en.get(signal, []))
        scam_phrases.extend(hi.get(signal, []))

    scam_phrases = [p for p in scam_phrases if len(p.split()) <= 6]
    scam_phrases = list(set(scam_phrases))

    safe_phrases = en.get("safe_phrases", []) + hi.get("safe_phrases", [])
    safe_phrases = list(set(safe_phrases))

    model = get_embeddings_model()
    logger.info(f"Encoding {len(scam_phrases)} scam phrases and {len(safe_phrases)} safe phrases...")
    _scam_embeddings = model.encode(scam_phrases, convert_to_numpy=True, show_progress_bar=False)
    _safe_embeddings = model.encode(safe_phrases, convert_to_numpy=True, show_progress_bar=False) if safe_phrases else None
    logger.info("Phrase cluster embeddings ready.")


def score_transcript(transcript: str) -> float:
    global _scam_embeddings, _safe_embeddings

    if _scam_embeddings is None:
        _build_phrase_clusters()

    model = get_embeddings_model()
    transcript_embedding = model.encode([transcript[:512]], convert_to_numpy=True)[0]

    scam_sims = np.dot(_scam_embeddings, transcript_embedding) / (
        np.linalg.norm(_scam_embeddings, axis=1) * np.linalg.norm(transcript_embedding) + 1e-8
    )

    top_k = min(5, len(scam_sims))
    top_scam_sim = float(np.mean(np.sort(scam_sims)[::-1][:top_k]))

    # Rescale: cosine similarity baseline noise floor is ~0.30-0.40 even for
    # unrelated text. Remap so only genuinely high similarity (0.55+) scores high.
    # Linear remap: sim <= 0.40 -> 0.0, sim >= 0.75 -> 1.0
    floor = 0.45
    ceiling = 0.65
    rescaled = (top_scam_sim - floor) / (ceiling - floor)
    rescaled = max(0.0, min(1.0, rescaled))

    safe_penalty = 0.0
    if _safe_embeddings is not None and len(_safe_embeddings) > 0:
        safe_sims = np.dot(_safe_embeddings, transcript_embedding) / (
            np.linalg.norm(_safe_embeddings, axis=1) * np.linalg.norm(transcript_embedding) + 1e-8
        )
        top_safe_sim = float(np.max(safe_sims))
        safe_penalty = max(0.0, top_safe_sim - 0.45) * 0.5

    final_score = max(0.0, min(1.0, rescaled - safe_penalty))
    return round(final_score, 4)