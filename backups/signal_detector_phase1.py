import os
import json
import logging
from typing import Dict, List, Tuple, Any
from core.ensemble import get_bart_pipeline

# Configure logger
logger = logging.getLogger("scam_detector.signal_detector")
logging.basicConfig(level=logging.INFO)

# Config file locations
CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config")
THRESHOLDS_PATH = os.path.join(CONFIG_DIR, "thresholds.json")
KEYWORDS_EN_PATH = os.path.join(CONFIG_DIR, "keywords_en.json")
KEYWORDS_HI_PATH = os.path.join(CONFIG_DIR, "keywords_hi.json")

os.makedirs(CONFIG_DIR, exist_ok=True)


def load_or_create_configs() -> Tuple[Dict[str, float], Dict[str, List[str]], Dict[str, List[str]]]:
    default_thresholds = {
        "demand": 0.65,
        "urgency": 0.60,
        "threat": 0.70,
        "manipulation": 0.15,
        "share_screen": 0.50,
        "personal_info": 0.60,
        "fake_rewards": 0.55
    }

    default_keywords_en = {
        "demand": ["transfer", "pay", "deposit", "amount", "wire", "transaction", "send money"],
        "urgency": ["immediately", "2 hours", "deadline", "fast", "right now", "hurry", "quick"],
        "threat": ["arrest", "warrant", "fir", "jail", "supreme court", "cbi", "police", "customs", "court"],
        "manipulation": ["don't tell anyone", "stay on call", "keep secret", "don't hang up", "family", "secret"],
        "share_screen": ["share screen", "screen share", "anydesk", "teamviewer", "remote access", "desktop share"],
        "personal_info": ["aadhaar", "pan", "otp", "cvv", "account number", "card number", "bank details", "pin"],
        "fake_rewards": ["you have won", "lucky draw", "prize money", "claim your prize", "lottery winner",
                         "tax refund", "ITR refund", "guaranteed returns", "monthly returns", "crypto profit",
                         "processing fee to claim", "GST on prize", "investment platform", "assured returns",
                         "bumper prize", "selected as winner", "congratulations winner", "KBC winner",
                         "refund pending", "prize transfer", "winning amount"]
    }

    default_keywords_hi = {
        "demand": ["bhejo", "paisa", "paise bhejo", "bhugtan", "jama", "transfer karo"],
        "urgency": ["abhi", "turant", "do ghante", "jaldi", "fauran", "jaldi karo"],
        "threat": ["giraftari", "hiraasat", "thaane", "court case", "police block", "kanooni karwai"],
        "manipulation": ["kisi ko mat batao", "family se mat bolo", "chup raho", "phone mat kaatna", "raaz rakho"],
        "share_screen": ["screen dikhao", "anydesk install karo", "screen control", "mobile screen"],
        "personal_info": ["khata number", "otp batao", "aadhaar card", "pan card", "card details"],
        "fake_rewards": ["inaam jeeta hai", "lucky draw winner", "prize claim karo", "refund pending hai",
                         "guaranteed returns", "monthly profit", "invest karo", "prize fee bharo"]
    }

    if not os.path.exists(THRESHOLDS_PATH):
        logger.info("Threshold configuration missing. Writing defaults...")
        with open(THRESHOLDS_PATH, "w", encoding="utf-8") as f:
            json.dump(default_thresholds, f, indent=2)
        thresholds = default_thresholds
    else:
        with open(THRESHOLDS_PATH, "r", encoding="utf-8") as f:
            thresholds = json.load(f)
        # Ensure fake_rewards threshold exists even in old thresholds files
        if "fake_rewards" not in thresholds:
            thresholds["fake_rewards"] = 0.55

    if not os.path.exists(KEYWORDS_EN_PATH):
        logger.info("English keyword configuration missing. Writing defaults...")
        with open(KEYWORDS_EN_PATH, "w", encoding="utf-8") as f:
            json.dump(default_keywords_en, f, indent=2)
        keywords_en = default_keywords_en
    else:
        with open(KEYWORDS_EN_PATH, "r", encoding="utf-8") as f:
            keywords_en = json.load(f)

    if not os.path.exists(KEYWORDS_HI_PATH):
        logger.info("Hindi keyword configuration missing. Writing defaults...")
        with open(KEYWORDS_HI_PATH, "w", encoding="utf-8") as f:
            json.dump(default_keywords_hi, f, indent=2)
        keywords_hi = default_keywords_hi
    else:
        with open(KEYWORDS_HI_PATH, "r", encoding="utf-8") as f:
            keywords_hi = json.load(f)

    return thresholds, keywords_en, keywords_hi


class SignalDetector:
    def __init__(self):
        self.thresholds, self.keywords_en, self.keywords_hi = load_or_create_configs()

        # 7 signals now — added fake_rewards
        self.label_mapping = {
            "demand": "demanding money transfers, payments, deposits, or fees",
            "urgency": "demanding immediate action or setting a strict deadline",
            "threat": "threatening law enforcement, arrest warrants, jail, or legal action",
            "manipulation": "instructing to keep secrets, stay on call, or isolate from family",
            "share_screen": "asking to share screen or download remote control apps like AnyDesk",
            "personal_info": "requesting sensitive personal details like OTP, Aadhaar, PAN, or bank cards",
            "fake_rewards": "offering fake prizes, lottery winnings, tax refunds, or guaranteed investment returns"
        }

    def detect_signals(self, transcript: str) -> Dict[str, Dict[str, Any]]:
        cleaned_transcript = transcript.strip()
        lower_transcript = cleaned_transcript.lower()

        results = {}

        if not cleaned_transcript:
            for signal in self.thresholds.keys():
                results[signal] = {
                    "score": 0.0,
                    "triggered": False,
                    "phrases_caught": []
                }
            return results

        # 1. BART multi-label zero-shot classification for all 7 signals
        logger.info("Evaluating multi-label BART classification for signal dimensions...")
        bart = get_bart_pipeline()
        candidate_labels = list(self.label_mapping.values())

        bart_res = bart(cleaned_transcript[:750], candidate_labels=candidate_labels, multi_label=True)
        zero_shot_scores = dict(zip(bart_res["labels"], bart_res["scores"]))

        # 2. Check for safe phrases — these reduce score across all signals
        safe_phrases = self.keywords_en.get("safe_phrases", [])
        safe_matches = sum(1 for p in safe_phrases if p.lower() in lower_transcript)
        # Each safe phrase match reduces score by 0.12, capped at 0.35 total reduction
        safe_penalty = min(0.35, safe_matches * 0.12)
        if safe_matches > 0:
            logger.info(f"Safe phrase matches: {safe_matches}, penalty: {safe_penalty:.2f}")

        # 3. Score each signal
        for signal_key, threshold in self.thresholds.items():
            en_keywords = self.keywords_en.get(signal_key, [])
            hi_keywords = self.keywords_hi.get(signal_key, [])
            combined_keywords = en_keywords + hi_keywords

            # Keyword matching
            phrases_caught = []
            for kw in combined_keywords:
                if kw.lower() in lower_transcript:
                    phrases_caught.append(kw)

            phrases_caught = list(dict.fromkeys(phrases_caught))

            # BART semantic score for this signal
            semantic_label = self.label_mapping.get(signal_key, "")
            zero_shot_score = float(zero_shot_scores.get(semantic_label, 0.0))

            # Keyword boost — each match adds 0.35 up to 1.0
            keyword_score = min(1.0, len(phrases_caught) * 0.35)

            # Combined score — 65% BART semantic + 35% keyword
            combined_score = (zero_shot_score * 0.65) + (keyword_score * 0.35)

            # Apply safe phrase penalty (not on manipulation — scammers also say "I'm helping you")
            if signal_key not in ["manipulation", "threat"]:
                combined_score = combined_score - safe_penalty

            combined_score = round(max(0.0, min(1.0, combined_score)), 2)
            if len(phrases_caught) >= 2:
                triggered = True
                combined_score = max(combined_score, threshold + 0.05)
            else:
                triggered = combined_score >= threshold
            

            results[signal_key] = {
                "score": combined_score,
                "triggered": triggered,
                "phrases_caught": phrases_caught
            }

        logger.info("Signal breakdown mapping calculations complete.")
        return results