import json
import requests
import time
import os

# Load test data
with open("scam_dataset.json", encoding="utf-8") as f:
    test_cases = json.load(f)

API_URL = "http://localhost:8000/detect/file"

results = []

correct = 0
total = len(test_cases)

print(f"\n{'='*65}")
print(f"  SCAM DETECTOR ACCURACY CHECK")
print(f"  Testing {total} cases — {sum(1 for c in test_cases if c['label']=='SCAM')} SCAM | "
      f"{sum(1 for c in test_cases if c['label']=='SAFE')} SAFE | "
      f"{sum(1 for c in test_cases if c['label']=='SUSPICIOUS')} SUSPICIOUS")
print(f"{'='*65}\n")

for case in test_cases:
    # Write text to temp file
    with open("_temp_test.txt", "w", encoding="utf-8") as f:
        f.write(case["text"])

    try:
        with open("_temp_test.txt", "rb") as f:
            response = requests.post(
                API_URL,
                files={"file": ("test.txt", f, "text/plain")},
                timeout=60
            )
        result = response.json()
        predicted = result.get("verdict", "ERROR")
        score = result.get("scam_score", 0)
        signals = result.get("signals_triggered", 0)

    except Exception as e:
        predicted = "ERROR"
        score = 0
        signals = 0
        print(f"  ERROR on case {case['id']}: {e}")

    actual = case["label"]

    # Scoring logic
    # SCAM label: correct if predicted SCAM
    # SAFE label: correct if predicted SAFE
    # SUSPICIOUS label: correct if predicted SUSPICIOUS or SCAM
    #   (suspicious cases should at least not be called SAFE)
    if actual == "SCAM":
        is_correct = predicted == "SCAM"
    elif actual == "SAFE":
        is_correct = predicted == "SAFE"
    elif actual == "SUSPICIOUS":
        is_correct = predicted in ["SUSPICIOUS", "SCAM"]
    else:
        is_correct = False

    if is_correct:
        correct += 1

    status = "✓" if is_correct else "✗"
    scam_type = case.get("scam_type", "")

    print(f"  {status}  [{case['id']:02d}] {actual:10s} → {predicted:10s} | "
          f"Score: {score:.2f} | Signals: {signals} | {scam_type}")

    results.append({
        "id": case["id"],
        "label": actual,
        "scam_type": scam_type,
        "predicted": predicted,
        "score": score,
        "signals_triggered": signals,
        "correct": is_correct
    })

    time.sleep(0.3)

# Cleanup temp file
if os.path.exists("_temp_test.txt"):
    os.remove("_temp_test.txt")

print(f"\n{'='*65}")

# Core metrics
accuracy = correct / total * 100

scam_cases      = [r for r in results if r["label"] == "SCAM"]
safe_cases      = [r for r in results if r["label"] == "SAFE"]
suspicious_cases = [r for r in results if r["label"] == "SUSPICIOUS"]

# SCAM metrics
true_positives  = sum(1 for r in scam_cases if r["predicted"] == "SCAM")
false_negatives = sum(1 for r in scam_cases if r["predicted"] != "SCAM")

# SAFE metrics
true_negatives  = sum(1 for r in safe_cases if r["predicted"] == "SAFE")
false_positives = sum(1 for r in safe_cases if r["predicted"] != "SAFE")

# SUSPICIOUS metrics
suspicious_correct = sum(1 for r in suspicious_cases if r["predicted"] in ["SUSPICIOUS", "SCAM"])
suspicious_wrong   = sum(1 for r in suspicious_cases if r["predicted"] == "SAFE")

# Precision, Recall, F1
precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
recall    = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

print(f"""
  RESULTS SUMMARY
  ─────────────────────────────────────────────────────
  Total cases        : {total}
  Correct            : {correct}
  Wrong              : {total - correct}
  Overall Accuracy   : {accuracy:.1f}%

  SCAM DETECTION
  ─────────────────────────────────────────────────────
  True positives     : {true_positives}/{len(scam_cases)}  (scams correctly caught)
  False negatives    : {false_negatives}/{len(scam_cases)}  (scams missed) ← dangerous

  SAFE CALL DETECTION
  ─────────────────────────────────────────────────────
  True negatives     : {true_negatives}/{len(safe_cases)}  (safe calls correctly cleared)
  False positives    : {false_positives}/{len(safe_cases)}  (safe calls wrongly flagged)

  SUSPICIOUS DETECTION
  ─────────────────────────────────────────────────────
  Correct (SUSPICIOUS or SCAM) : {suspicious_correct}/{len(suspicious_cases)}
  Wrong (called SAFE)          : {suspicious_wrong}/{len(suspicious_cases)}  ← risky

  MODEL QUALITY
  ─────────────────────────────────────────────────────
  Precision          : {precision*100:.1f}%   (of flagged scams, how many were real)
  Recall             : {recall*100:.1f}%   (of real scams, how many we caught)
  F1 Score           : {f1:.3f}  (balance of precision and recall)
  ─────────────────────────────────────────────────────
""")

# Failed cases breakdown
failed = [r for r in results if not r["correct"]]
if failed:
    print("  FAILED CASES:")
    for r in failed:
        print(f"    [{r['id']:02d}] {r['label']:10s} → predicted {r['predicted']:10s} "
              f"(score {r['score']:.2f}) — {r['scam_type']}")
    print()

# Grade
if accuracy >= 90:
    grade = "EXCELLENT ★★★★★"
elif accuracy >= 80:
    grade = "GOOD ★★★★"
elif accuracy >= 70:
    grade = "ACCEPTABLE ★★★"
elif accuracy >= 60:
    grade = "NEEDS IMPROVEMENT ★★"
else:
    grade = "POOR ★"

print(f"  GRADE: {grade}")
print(f"{'='*65}\n")

# Save full report
report = {
    "accuracy": round(accuracy, 2),
    "precision": round(precision * 100, 2),
    "recall": round(recall * 100, 2),
    "f1_score": round(f1, 3),
    "total_cases": total,
    "correct": correct,
    "wrong": total - correct,
    "true_positives": true_positives,
    "false_negatives": false_negatives,
    "true_negatives": true_negatives,
    "false_positives": false_positives,
    "suspicious_correct": suspicious_correct,
    "suspicious_wrong": suspicious_wrong,
    "grade": grade,
    "cases": results
}

with open("accuracy_report.json", "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, ensure_ascii=False)

print("  Full report saved to accuracy_report.json\n")