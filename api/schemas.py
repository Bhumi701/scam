from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict


class SignalDetail(BaseModel):
    """
    Detailed breakdown of a specific signal trigger.
    """
    score: float = Field(..., description="Calculated probability or confidence score for the signal [0.0 - 1.0]")
    triggered: bool = Field(..., description="Indicates if the calculated score meets or exceeds the defined signal threshold")
    phrases_caught: List[str] = Field(..., description="List of keyword/phrase matches captured from the transcript")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "score": 0.88,
                "triggered": True,
                "phrases_caught": ["transfer karo", "5 lakh"]
            }
        }
    )


class SignalsBreakdown(BaseModel):
    """
    Container object grouping all 6 tracked signal outputs.
    """
    demand: SignalDetail = Field(..., description="Financial pay or deposit requests")
    urgency: SignalDetail = Field(..., description="High pressure timelines or immediate action warnings")
    threat: SignalDetail = Field(..., description="Law enforcement, police, arrest warrants, or court action warnings")
    manipulation: SignalDetail = Field(..., description="Secrecy orders or requests to isolate from family members")
    share_screen: SignalDetail = Field(..., description="Demands to share phone screens or install remote access software")
    personal_info: SignalDetail = Field(..., description="Requests for KYC documents, Aadhaar, PAN, OTP, or CVV")
    fake_rewards: SignalDetail
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "demand": {"score": 0.88, "triggered": True, "phrases_caught": ["transfer karo"]},
                "urgency": {"score": 0.94, "triggered": True, "phrases_caught": ["2 ghante mein"]},
                "threat": {"score": 0.87, "triggered": True, "phrases_caught": ["arrest warrant"]},
                "manipulation": {"score": 0.76, "triggered": True, "phrases_caught": ["kisi ko mat batao"]},
                "share_screen": {"score": 0.0, "triggered": False, "phrases_caught": []},
                "personal_info": {"score": 0.91, "triggered": True, "phrases_caught": ["Aadhaar", "OTP"]}
            }
        }
    )


class ScamDetectionResponse(BaseModel):
    """
    Standard unified schema returned on both file analysis and realtime sessions.
    """
    scam_score: float = Field(..., description="Final combined scam score [0.0 - 1.0] from the model ensemble")
    verdict: str = Field(..., description="Calculated call state: 'SCAM', 'SUSPICIOUS', or 'SAFE'")
    confidence_band: str = Field(..., description="System accuracy assessment: 'HIGH', 'MEDIUM', or 'LOW'")
    signals: SignalsBreakdown = Field(..., description="Granular breakdown of the 6 core signal metrics")
    signals_triggered: int = Field(..., description="Total count of active/triggered signals detected")
    summary: str = Field(..., description="2-line summarizing assessment highlight of risk factors")
    language: str = Field(..., description="Primary conversation language detected (Hindi, English, Hinglish)")
    transcript: str = Field(..., description="Completed or accumulated processed text transcription")
    mode: str = Field(..., description="Processing pipeline mode: 'file' or 'realtime'")
    processing_time_ms: int = Field(..., description="Inference engine processing duration in milliseconds")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "scam_score": 0.91,
                "verdict": "SCAM",
                "confidence_band": "HIGH",
                "signals": {
                    "demand": {"score": 0.88, "triggered": True, "phrases_caught": ["transfer karo", "5 lakh"]},
                    "urgency": {"score": 0.94, "triggered": True, "phrases_caught": ["2 ghante mein"]},
                    "threat": {"score": 0.87, "triggered": True, "phrases_caught": ["arrest warrant"]},
                    "manipulation": {"score": 0.76, "triggered": True, "phrases_caught": ["kisi ko mat batao"]},
                    "share_screen": {"score": 0.0, "triggered": False, "phrases_caught": []},
                    "personal_info": {"score": 0.91, "triggered": True, "phrases_caught": ["Aadhaar", "OTP"]}
                },
                "signals_triggered": 5,
                "summary": "Caller impersonated CBI officer, threatened arrest, demanded Aadhaar and OTP.",
                "language": "Hinglish",
                "transcript": "Aapka arrest warrant nikla hai CBI se. AnyDesk download karke verification karayein aur do ghante me transfer karo paise tabhi block katega. OTP aur Aadhaar number share karein, kisi ko mat batana.",
                "mode": "file",
                "processing_time_ms": 4200
            }
        }
    )


class SessionStartResponse(BaseModel):
    """
    Response schema indicating successful starting of a real-time call tracking session.
    """
    session_id: str = Field(..., description="Unique UUID format string assigned to track the real-time stream")
    status: str = Field("started", description="Initial session state indicator")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "session_id": "8f3b9c5a-1122-3344-5566-778899aabbcc",
                "status": "started"
            }
        }
    )


class SessionStatusResponse(BaseModel):
    """
    Intermediary response returned upon checking live stats on an open session without pushing chunks.
    """
    session_id: str = Field(..., description="Tracking UUID")
    scam_score: float = Field(..., description="Running combined leaky integrator score")
    verdict: str = Field(..., description="Current running status assessment")
    confidence_band: str = Field(..., description="Current classification confidence band")
    signals_triggered: int = Field(..., description="Number of currently active signal metrics")
    transcript_so_far: str = Field(..., description="Accumulated conversational text transcribed up to this point")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "session_id": "8f3b9c5a-1122-3344-5566-778899aabbcc",
                "scam_score": 0.63,
                "verdict": "SUSPICIOUS",
                "confidence_band": "MEDIUM",
                "signals_triggered": 2,
                "transcript_so_far": "Hello, pay me immediately please."
            }
        }
    )


class TextAnalyzeRequest(BaseModel):
    """
    Optional payload schema for testing pure text scanning endpoints.
    """
    text: str = Field(..., min_length=1, description="Raw transcription text input to evaluate")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "text": "Your account is blocked, call customer service now to pay verification charges."
            }
        }
    )