# Scam Detection API — Frontend Integration Guide

## Base URL

```
http://localhost:8000
```

(Update to your deployed host/port once this moves off local dev.)

## Endpoint

### `POST /detect/file`

Accepts an audio, video, text, or image file, runs it through the full detection pipeline (transcription/OCR → ensemble scoring → signal detection → rule engine), and returns a complete scam risk profile.

**Content-Type:** `multipart/form-data`

**Form field:**

| Field | Type | Required | Notes |
|---|---|---|---|
| `file` | File | Yes | Audio, video, text, or image file to analyze |

---

## Response

**Content-Type:** `application/json`

```json
{
  "scam_score": 0.85,
  "verdict": "SCAM",
  "confidence_band": "HIGH",
  "signals": {
    "demand": { "score": 0.72, "triggered": true, "phrases_caught": ["transfer"] },
    "urgency": { "score": 0.65, "triggered": true, "phrases_caught": ["immediately"] },
    "threat": { "score": 0.80, "triggered": true, "phrases_caught": ["arrest", "police"] },
    "manipulation": { "score": 0.30, "triggered": false, "phrases_caught": [] },
    "share_screen": { "score": 0.00, "triggered": false, "phrases_caught": [] },
    "personal_info": { "score": 0.55, "triggered": false, "phrases_caught": [] },
    "fake_rewards": { "score": 0.00, "triggered": false, "phrases_caught": [] }
  },
  "signals_triggered": 3,
  "summary": "Caller claims to be law enforcement and demands immediate payment.",
  "language": "Hinglish",
  "transcript": "Main CBI se bol raha hoon...",
  "mode": "file",
  "processing_time_ms": 4213
}
```

### Field reference

| Field | Type | Description |
|---|---|---|
| `scam_score` | float (0–1) | Final risk score, rounded to 2 decimals |
| `verdict` | string | One of `"SCAM"`, `"SUSPICIOUS"`, `"SAFE"` |
| `confidence_band` | string | One of `"HIGH"`, `"MEDIUM"`, `"LOW"` |
| `signals` | object | Per-signal breakdown — see below |
| `signals_triggered` | int | Count of signal categories that crossed their trigger threshold |
| `summary` | string | 2-line auto-generated summary of the transcript |
| `language` | string | `"English"`, `"Hindi"`, `"Hinglish"`, or `"Multilingual (xx)"` |
| `transcript` | string | Full transcribed/extracted text |
| `mode` | string | Always `"file"` for this endpoint |
| `processing_time_ms` | int | Server-side processing time in milliseconds |

**`signals` object** — one entry per category (`demand`, `urgency`, `threat`, `manipulation`, `share_screen`, `personal_info`, `fake_rewards`), each shaped as:

| Field | Type | Description |
|---|---|---|
| `score` | float (0–1) | Confidence for this specific signal |
| `triggered` | bool | Whether this signal crossed its threshold |
| `phrases_caught` | string[] | Matched keywords/phrases for this signal, if any |

> **Note:** the exact field types above are derived from the current implementation, not a published OpenAPI spec — if your team has strict typing needs (e.g., generating TS types), I'd recommend pulling `/openapi.json` from the running server (FastAPI generates this automatically) rather than hand-typing against this doc, since it'll always match the live schema exactly.

### Error response

On any pipeline failure, the endpoint returns:

```json
{
  "detail": "Internal scanning engine failure: <error message>"
}
```

with HTTP status `500`.

---

## Example requests

### curl
```bash
curl -X POST http://localhost:8000/detect/file \
  -F "file=@sample.txt;type=text/plain"
```

### JavaScript (fetch)
```javascript
async function checkForScam(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch("http://localhost:8000/detect/file", {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.detail || "Detection request failed");
  }

  return response.json(); // -> the response shape documented above
}
```

### JavaScript (axios)
```javascript
import axios from "axios";

async function checkForScam(file) {
  const formData = new FormData();
  formData.append("file", file);

  const { data } = await axios.post(
    "http://localhost:8000/detect/file",
    formData,
    { headers: { "Content-Type": "multipart/form-data" } }
  );

  return data;
}
```

### React file input example
```jsx
function ScamChecker() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleFileChange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setLoading(true);
    try {
      const data = await checkForScam(file);
      setResult(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <input type="file" onChange={handleFileChange} />
      {loading && <p>Analyzing...</p>}
      {result && (
        <div>
          <p>Verdict: {result.verdict} ({result.confidence_band})</p>
          <p>Score: {result.scam_score}</p>
        </div>
      )}
    </div>
  );
}
```

---

## CORS setup (backend — needed before a browser can call this)

Browsers block cross-origin requests by default. Since the frontend almost certainly runs on a different origin (e.g., `localhost:3000`) than the API (`localhost:8000`), you need to add CORS middleware to your FastAPI app — **this goes in `api/main.py`** (wherever `FastAPI()` is instantiated), not in `routes_file.py`:

```python
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()  # your existing app instance

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",   # your frontend dev server
        # add your deployed frontend URL here too, e.g.:
        # "https://yourapp.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

Add this **before** `app.include_router(...)` calls. Without it, the frontend will get CORS errors in the browser console even though `curl`/Postman work fine (those aren't subject to browser CORS rules).

**Security note for later:** `allow_origins=["*"]` is easy but should not go to production — list actual frontend domains explicitly, as above.

---

## Practical notes for the frontend team

- **Processing time varies significantly** — audio/video files requiring transcription plus full ensemble scoring can take several seconds to over a minute depending on length and server load. Build the UI around this (loading state, don't assume near-instant response) rather than treating it as an edge case.
- **File size limits:** not currently enforced at the API level in what I've reviewed — worth confirming with backend before allowing arbitrarily large uploads from the client.
- **No authentication is currently implemented** on this endpoint based on the code reviewed — flag this to whoever owns deployment before this goes anywhere public-facing.
