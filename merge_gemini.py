import json

def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def merge_lists(*lists):
    seen = set()
    result = []
    for lst in lists:
        if not isinstance(lst, list):
            continue
        for item in lst:
            if not isinstance(item, str):
                continue
            key = item.lower().strip()
            if key not in seen:
                seen.add(key)
                result.append(item)
    return result

# Load existing keyword files
en = load("config/keywords_en.json")
hi = load("config/keywords_hi.json")

# Load Gemini output
gemini = load("gemini_output.json")

# Gemini has keywords_en at top level
g_en = gemini.get("keywords_en", {})
g_hi = gemini.get("keywords_hi", {})
g_hl = gemini.get("keywords_hinglish", {})

# These are the signal categories your system uses
signal_categories = [
    "demand", "urgency", "threat", "manipulation",
    "share_screen", "personal_info"
]

# These are bonus/extra categories
extra_categories = [
    "authority_impersonation", "fake_rewards", "financial_pressure",
    "isolation", "remote_access_tools", "fake_departments",
    "payment_methods_scammers_use", "safe_phrases",
    "authority_names", "scam_type_openers"
]

all_categories = signal_categories + extra_categories

# Merge English — existing + gemini english + gemini hinglish
for cat in all_categories:
    existing = en.get(cat, [])
    from_gemini_en = g_en.get(cat, [])
    from_gemini_hl = g_hl.get(cat, [])
    en[cat] = merge_lists(existing, from_gemini_en, from_gemini_hl)

# Merge Hindi — existing + gemini hindi + gemini hinglish
for cat in all_categories:
    existing = hi.get(cat, [])
    from_gemini_hi = g_hi.get(cat, [])
    from_gemini_hl = g_hl.get(cat, [])
    hi[cat] = merge_lists(existing, from_gemini_hi, from_gemini_hl)

# Gemini also put safe_phrases at top level of keywords_en
# make sure they are included
gemini_safe = g_en.get("safe_phrases", [])
en["safe_phrases"] = merge_lists(en.get("safe_phrases", []), gemini_safe)

# Also grab safe_phrases from hindi side
gemini_safe_hi = g_hi.get("safe_phrases", [])
hi["safe_phrases"] = merge_lists(hi.get("safe_phrases", []), gemini_safe_hi)

# Save merged files
with open("config/keywords_en.json", "w", encoding="utf-8") as f:
    json.dump(en, f, indent=2, ensure_ascii=False)

with open("config/keywords_hi.json", "w", encoding="utf-8") as f:
    json.dump(hi, f, indent=2, ensure_ascii=False)

# Print stats
print("\nMerge complete!\n")
print("keywords_en.json:")
total_en = 0
for cat, phrases in en.items():
    if phrases:
        print(f"  {cat:35s}: {len(phrases):4d} phrases")
        total_en += len(phrases)

print(f"\nkeywords_hi.json:")
total_hi = 0
for cat, phrases in hi.items():
    if phrases:
        print(f"  {cat:35s}: {len(phrases):4d} phrases")
        total_hi += len(phrases)

print(f"\nTotal English phrases : {total_en}")
print(f"Total Hindi phrases   : {total_hi}")
print(f"Grand total           : {total_en + total_hi}")
print("\nNow run: python setup_xgb.py")