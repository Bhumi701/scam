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

# Load existing files (keep all long phrases)
en = load("config/keywords_en.json")
hi = load("config/keywords_hi.json")

# Short phrases to ADD on top of whatever is already there
short_en = {
    "demand": [
        "transfer", "send money", "deposit", "pay", "payment", "wire transfer",
        "UPI", "Google Pay", "PhonePe", "Paytm", "BHIM",
        "processing fee", "security deposit", "verification fee", "activation fee",
        "clearance fee", "handling fee", "bail amount", "court fee",
        "transfer to safe account", "safe account", "RBI account",
        "gift card", "iTunes card", "Amazon voucher", "crypto", "Bitcoin",
        "refundable deposit", "compliance fee", "settlement amount",
        "pay before", "send before", "transfer within", "customs duty",
        "token amount", "advance payment", "unblock fee"
    ],
    "urgency": [
        "immediately", "right now", "last chance", "final warning", "act now",
        "within 2 hours", "within 30 minutes", "before midnight", "today only",
        "deadline", "time is running out", "warrant will be issued",
        "urgent", "emergency", "critical", "account blocked in 2 hours",
        "SIM blocked tonight", "police on the way", "officer dispatched",
        "24 hours", "2 hours", "30 minutes", "don't hang up",
        "stay on the line", "do not disconnect", "final notice",
        "arrest warrant active", "non-bailable warrant", "summons issued"
    ],
    "threat": [
        "arrest", "arrested", "arrest warrant", "non-bailable warrant",
        "FIR", "criminal charges", "under investigation", "under surveillance",
        "assets seized", "accounts frozen", "property attached",
        "passport cancelled", "travel ban", "money laundering", "narcotics",
        "drug case", "cybercrime", "fraud suspect", "jail", "prison",
        "Supreme Court", "court summons", "case registered", "warrant",
        "CBI", "Enforcement Directorate", "ED", "income tax raid",
        "interpol", "red corner notice", "electricity will be cut",
        "disconnecting means guilty", "SIM suspended", "TRAI blacklist"
    ],
    "manipulation": [
        "we are trying to help you", "I am on your side", "trust me",
        "this is your only way out", "cooperate and everything will be fine",
        "don't panic", "no one needs to know", "settle this between us",
        "completely confidential", "don't tell anyone", "keep this secret",
        "do not tell family", "stay on call", "don't hang up",
        "just follow my instructions", "do exactly as I say",
        "security protocol", "standard procedure", "for your protection",
        "hackers targeting your account", "RBI flagged your account",
        "if you cooperate this won't go on your record",
        "other people didn't cooperate and are in jail"
    ],
    "share_screen": [
        "AnyDesk", "TeamViewer", "QuickSupport", "Supremo", "AirDroid",
        "AirMirror", "RemotePC", "LogMeIn", "Splashtop", "RustDesk",
        "Ammyy Admin", "ScreenConnect", "Bomgar", "Zoho Assist",
        "Chrome Remote Desktop", "download AnyDesk", "install TeamViewer",
        "share your screen", "give remote access", "allow screen sharing",
        "9 digit code", "AnyDesk code", "display ID", "share the code",
        "read out the code", "allow permissions", "click allow all",
        "remote verification", "APK file", "download from this link",
        "fake banking app", "fake RBI app", "keep the app running",
        "don't close the app", "I will log into your bank"
    ],
    "personal_info": [
        "Aadhaar", "PAN", "OTP", "CVV", "account number", "IFSC",
        "credit card number", "card number", "card PIN", "ATM PIN",
        "internet banking password", "net banking", "UPI PIN", "MPIN",
        "transaction password", "voter ID", "passport number",
        "driving license", "insurance policy number",
        "send selfie with Aadhaar", "WhatsApp your documents",
        "email your KYC", "share your bank statement",
        "how much balance", "bank statement"
    ],
    "authority_impersonation": [
        "calling from CBI", "CBI officer", "CBI headquarters",
        "Delhi police cybercrime", "Mumbai cybercrime",
        "Income Tax Department", "TRAI authority",
        "RBI special investigation", "Reserve Bank of India",
        "Enforcement Directorate", "ED officer",
        "Narcotics Control Bureau", "NCB officer",
        "IPS officer", "DCP", "court summons officer",
        "customs department", "Supreme Court notice",
        "Ministry of Home Affairs", "SEBI investigation",
        "INTERPOL", "FBI India", "UN fraud department"
    ],
    "safe_phrases": [
        "we will never ask for your OTP",
        "please do not share your PIN",
        "please visit your nearest branch",
        "we do not ask for remote access",
        "we never ask for gift card payments",
        "no government agency asks for payment via UPI on phone",
        "please take your time there is no rush",
        "you can have a family member present",
        "we will send you written communication",
        "no court issues arrest orders over phone",
        "please call 1930 to report cyber fraud",
        "CBI never makes phone calls to announce arrests",
        "if in doubt hang up and call us back",
        "visit the branch", "come to the office",
        "bring original documents", "appointment tomorrow",
        "in person verification", "physical copy required",
        "please visit us", "walk in anytime"
    ]
}

short_hi = {
    "demand": [
        "bhejo", "paisa bhejo", "paise bhejo", "transfer karo", "jama karo",
        "bhugtan karo", "fee bharo", "payment karo", "rakam bhejo",
        "rupaye bhejo", "turant bhejo", "abhi bhejo", "UPI karo",
        "Google Pay karo", "PhonePe karo", "Paytm karo",
        "safe account mein transfer karo", "RBI account mein bhejo",
        "gift card kharido", "crypto mein do", "bail amount bharo"
    ],
    "urgency": [
        "abhi", "turant", "jaldi karo", "fauran", "aaj hi",
        "abhi ke abhi", "do ghante mein", "30 minute mein",
        "kal tak", "time kam hai", "aaj raat tak",
        "police aa rahi hai", "warrant issue ho raha hai",
        "account band ho jayega", "SIM block ho jayegi",
        "bijli kat jayegi", "phone mat kaatna", "line par raho",
        "disconnect mat karo", "abhi nahi toh kabhi nahi"
    ],
    "threat": [
        "giraftari", "arrest hoga", "jail jayenge", "FIR darj",
        "warrant nikla hai", "thaane le jayenge", "court case",
        "kanooni karwai", "police aayegi", "CBI hai", "cyber police",
        "ED investigation", "income tax raid", "account freeze",
        "property attach", "passport cancel", "money laundering",
        "drug case", "narcotics", "TRAI ne block kiya",
        "number blacklist", "SIM band", "bijli kategi",
        "Aadhaar misuse", "PAN card case mein", "Supreme Court",
        "warrant", "criminal record"
    ],
    "manipulation": [
        "kisi ko mat batao", "kisi ko mat batana", "kisi se mat bolna",
        "family ko mat batao", "ghar mein kisiko mat bolna",
        "chup raho", "phone mat kaatna", "raaz rakho",
        "akele raho", "secret mein rakho", "hum aapki madad kar rahe hain",
        "main aapki taraf hoon", "mujh par trust karo",
        "yahi ek rasta hai", "cooperate karo sab theek ho jayega",
        "ghabrao mat", "bilkul confidential hai",
        "sirf mere instructions follow karo",
        "doosre log jail mein hain jo cooperate nahi kiye",
        "koi jaanne ki zaroorat nahi"
    ],
    "share_screen": [
        "AnyDesk", "TeamViewer", "screen share karo", "screen dikhao",
        "app install karo", "remote access do", "code batao",
        "display ID batao", "9 digit code", "permission do",
        "allow karo", "app mat band karo", "link se download karo",
        "verification app download karo", "RBI app install karo",
        "apna screen dikhao", "bank app kholo", "mobile dikhao"
    ],
    "personal_info": [
        "OTP batao", "OTP share karo", "Aadhaar number batao",
        "PAN card number", "ATM PIN", "khata number",
        "bank ka password", "UPI PIN batao", "MPIN",
        "card details", "CVV number", "credit card number",
        "net banking password", "account number batao", "IFSC code",
        "kitna balance hai", "bank statement bhejo",
        "voter ID", "passport number", "selfie bhejo Aadhaar ke saath",
        "document WhatsApp karo", "KYC document bhejo"
    ],
    "safe_phrases": [
        "hum aapse OTP kabhi nahi maangenge",
        "apna PIN kisi ko mat batayein",
        "nazdiki branch mein jaiye",
        "hum remote access nahi maangte",
        "gift card payment nahi hoti",
        "koi bhi government agency phone par UPI payment nahi maangti",
        "aap family member ko saath rakh sakte hain",
        "hum likhit mein communication bhejenge",
        "phone par arrest order nahi hota",
        "1930 par cyber fraud report karein",
        "CBI phone karke arrest announce nahi karta",
        "shak ho toh phone kaatein aur wapas call karein",
        "branch mein aaiye", "office mein aayein",
        "original documents laiye", "kal appointment hai",
        "personally aakar verify karein"
    ]
}

# Merge — existing long phrases KEPT, short phrases ADDED
for cat, phrases in short_en.items():
    en[cat] = merge_lists(en.get(cat, []), phrases)

for cat, phrases in short_hi.items():
    hi[cat] = merge_lists(hi.get(cat, []), phrases)

# Save
with open("config/keywords_en.json", "w", encoding="utf-8") as f:
    json.dump(en, f, indent=2, ensure_ascii=False)

with open("config/keywords_hi.json", "w", encoding="utf-8") as f:
    json.dump(hi, f, indent=2, ensure_ascii=False)

# Stats
total_en = sum(len(v) for v in en.values())
total_hi = sum(len(v) for v in hi.values())
print(f"keywords_en.json: {total_en} phrases across {len(en)} categories")
print(f"keywords_hi.json: {total_hi} phrases across {len(hi)} categories")
print(f"Grand total: {total_en + total_hi} phrases")
print("\nExisting long phrases KEPT. Short phrases ADDED on top.")
print("Now run: python setup_xgb.py")
