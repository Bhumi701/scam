import json
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from xgboost import XGBClassifier

# Load all keyword files (unchanged from original)
with open("config/keywords_en.json", encoding="utf-8") as f:
    en = json.load(f)
with open("config/keywords_hi.json", encoding="utf-8") as f:
    hi = json.load(f)

# Load new diverse safe-conversation corpora (15 domains, EN + HI)
with open("config/safe_conversations_en.json", encoding="utf-8") as f:
    safe_conv_en = json.load(f)
with open("config/safe_conversations_hi.json", encoding="utf-8") as f:
    safe_conv_hi = json.load(f)

# Load new ambiguous/suspicious conversation corpora (8 categories, EN + HI)
# Each file has two buckets: "ambiguous_safe" (-> label 0) and "ambiguous_scam" (-> label 1)
with open("config/ambiguous_conversations_en.json", encoding="utf-8") as f:
    ambiguous_en = json.load(f)
with open("config/ambiguous_conversations_hi.json", encoding="utf-8") as f:
    ambiguous_hi = json.load(f)

# Collect ALL scam phrases from every category in both files (unchanged from original)
scam_texts = []

for category, phrases in en.items():
    if category == "safe_phrases":
        continue
    if isinstance(phrases, list):
        scam_texts.extend(phrases)

for category, phrases in hi.items():
    if category == "safe_phrases":
        continue
    if isinstance(phrases, list):
        scam_texts.extend(phrases)

# Safe phrases become negative examples (unchanged from original)
safe_texts = en.get("safe_phrases", []) + hi.get("safe_phrases", [])

# ── NEW: fold in the diverse safe-conversation corpus (15 domains, EN + HI) ──
# Replaces the old 40-line hardcoded extra_safe list. This directly targets the
# diagnosed root cause: the safe class previously had ~16x less topical
# diversity than the scam class, causing XGBoost to learn "absence of narrow
# safe template" rather than genuine scam discrimination.
for domain, phrases in safe_conv_en.items():
    safe_texts.extend(phrases)
for domain, phrases in safe_conv_hi.items():
    safe_texts.extend(phrases)

# ── NEW: fold in ambiguous examples, hard-labeled by their actual ground truth ──
# Stays strictly binary — no third class, no soft labels, no objective change.
# ambiguous_safe -> safe class (0): scam-adjacent vocabulary, genuinely legitimate.
# ambiguous_scam -> scam class (1): real scam attempts using softer, less
#                                    templated language than the keyword-derived phrases.
for category, phrases in ambiguous_en["ambiguous_safe"].items():
    safe_texts.extend(phrases)
for category, phrases in ambiguous_hi["ambiguous_safe"].items():
    safe_texts.extend(phrases)

for category, phrases in ambiguous_en["ambiguous_scam"].items():
    scam_texts.extend(phrases)
for category, phrases in ambiguous_hi["ambiguous_scam"].items():
    scam_texts.extend(phrases)

# Remove duplicates (unchanged from original)
scam_texts = list(set(scam_texts))
safe_texts = list(set(safe_texts))

print(f"Scam phrases: {len(scam_texts)}")
print(f"Safe phrases (unique, pre-balance): {len(safe_texts)}")

# Balance the dataset — upsample safe to match scam count.
# Mechanism is unchanged from the original (random.choice with replacement),
# but the source pool is now ~570 unique strings instead of ~183, so the
# duplication ratio drops from roughly 19x to roughly 6x for the same target count.
import random
random.seed(42)
safe_pool = list(safe_texts)  # preserve the diverse pool to sample from
while len(safe_texts) < len(scam_texts):
    safe_texts.append(random.choice(safe_pool))

X = scam_texts + safe_texts
y = [1] * len(scam_texts) + [0] * len(safe_texts)

print(f"Total training samples: {len(X)}")
print(f"Scam: {sum(y)} | Safe: {len(y) - sum(y)}")

# Train TF-IDF with better settings for phrase detection
# UNCHANGED from original — no TF-IDF parameter tuning per task constraints.
vectorizer = TfidfVectorizer(
    ngram_range=(1, 3),        # capture up to 3-word phrases
    min_df=1,                  # include even rare phrases
    max_features=25000,        # allow up to 10k features
    sublinear_tf=True,         # better scaling
    analyzer="word",
    token_pattern=r"(?u)\b\w+\b"
)

X_vec = vectorizer.fit_transform(X)
print(f"TF-IDF features: {X_vec.shape[1]}")

# Train XGBoost
# UNCHANGED from original — no hyperparameter tuning, no calibration wrapper,
# per task constraints. Those are evaluated only after retraining on this dataset.
model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    use_label_encoder=False,
    eval_metric="logloss",
    random_state=42
)
model.fit(X_vec, y)

# Save models (unchanged from original — same paths, same format, same schema)
with open("models/xgb_model.pkl", "wb") as f:
    pickle.dump(model, f)
with open("models/tfidf_vectorizer.pkl", "wb") as f:
    pickle.dump(vectorizer, f)

print(f"\nDone.")
print(f"Features learned: {model.n_features_in_}")
print(f"Classes: {model.n_classes_}")
print("Models saved to models/")

# Quick sanity test (unchanged from original)
test_scam = "You will be arrested. Transfer money to safe account immediately. Share your Aadhaar and OTP."
test_safe = "Your order has been dispatched. Expected delivery tomorrow. Thank you."

test_vec = vectorizer.transform([test_scam, test_safe])
preds = model.predict_proba(test_vec)

print(f"\nSanity check:")
print(f"Scam text score:  {preds[0][1]:.2f} (should be high)")
print(f"Safe text score:  {preds[1][1]:.2f} (should be low)")