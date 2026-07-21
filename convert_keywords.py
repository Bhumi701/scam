import json

# Load the generated dataset
with open("india_scam_detection_dataset.json") as f:
    data = json.load(f)

en = data.get("keywords_en", {})
hi = data.get("keywords_hi", {})
hl = data.get("keywords_hinglish", {})

def merge(*dicts_for_key, key):
    result = []
    for d in dicts_for_key:
        result.extend(d.get(key, []))
    # deduplicate while preserving order
    seen = set()
    out = []
    for item in result:
        lower = item.lower()
        if lower not in seen:
            seen.add(lower)
            out.append(item)
    return out

signals = ["demand", "urgency", "threat", "manipulation",
           "share_screen", "personal_info"]

# keywords_en.json — English only
keywords_en = {}
for sig in signals:
    keywords_en[sig] = en.get(sig, [])

# Add extra useful categories as bonus signals
keywords_en["authority_impersonation"] = en.get("authority_impersonation", [])
keywords_en["fake_rewards"] = en.get("fake_rewards", [])
keywords_en["financial_pressure"] = en.get("financial_pressure", [])
keywords_en["isolation"] = en.get("isolation", [])
keywords_en["remote_access_tools"] = data.get("remote_access_tools", [])
keywords_en["fake_departments"] = data.get("fake_departments", [])
keywords_en["payment_methods_scammers_use"] = data.get("payment_methods_scammers_use", [])
keywords_en["safe_phrases"] = data.get("safe_phrases", [])
keywords_en["scam_type_openers"] = []
for stype, phrases in data.get("scam_types", {}).items():
    keywords_en["scam_type_openers"].extend(phrases)

# keywords_hi.json — Hindi + Hinglish merged
keywords_hi = {}
for sig in signals:
    keywords_hi[sig] = merge(hi, hl, key=sig)

keywords_hi["authority_impersonation"] = merge(hi, hl, key="authority_impersonation")
keywords_hi["fake_rewards"] = merge(hi, hl, key="fake_rewards")
keywords_hi["financial_pressure"] = merge(hi, hl, key="financial_pressure")
keywords_hi["isolation"] = merge(hi, hl, key="isolation")

# authority_names from the dataset
keywords_en["authority_names"] = data.get("authority_names", [])

with open("config/keywords_en.json", "w", encoding="utf-8") as f:
    json.dump(keywords_en, f, indent=2, ensure_ascii=False)

with open("config/keywords_hi.json", "w", encoding="utf-8") as f:
    json.dump(keywords_hi, f, indent=2, ensure_ascii=False)

# Count total phrases
total_en = sum(len(v) for v in keywords_en.values())
total_hi = sum(len(v) for v in keywords_hi.values())

print(f"keywords_en.json: {total_en} phrases across {len(keywords_en)} categories")
print(f"keywords_hi.json: {total_hi} phrases across {len(keywords_hi)} categories")
print("Done. Now run: python setup_xgb.py")