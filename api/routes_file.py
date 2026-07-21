import os
import time
import json
import logging
import tempfile
from fastapi import APIRouter, File, UploadFile, HTTPException
from api.schemas import ScamDetectionResponse, SignalsBreakdown, SignalDetail
from core.transcriber import Transcriber
from core.ensemble import predict_ensemble
from core.signal_detector import SignalDetector
from core.summarizer import Summarizer

# Configure logger
logger = logging.getLogger("scam_detector.api.file")
logging.basicConfig(level=logging.INFO)

router = APIRouter()

# Initialize core component singletons
transcriber = Transcriber()
signal_detector = SignalDetector()
summarizer = Summarizer()


@router.post("/file", response_model=ScamDetectionResponse)
async def detect_file(file: UploadFile = File(...)):
    """
    Accepts multipart file uploads (audio, video, text, or image files).
    Performs transcription, keyword-semantic signal verification, ensemble scoring,
    and returns a complete scam risk profile.
    """
    logger.info(f"Received file upload request. File Name: '{file.filename}', Content-Type: '{file.content_type}'")
    
    start_time = time.perf_counter()
    temp_file_path = None

    try:
        # Create a secure temporary file to write the upload stream
        suffix = os.path.splitext(file.filename)[1] if file.filename else ""
        temp_fd, temp_file_path = tempfile.mkstemp(suffix=suffix)
        
        # Stream upload file data into the temporary system file
        with os.fdopen(temp_fd, 'wb') as tmp:
            content = await file.read()
            tmp.write(content)

        # 1. Pipeline Stage: Audio Extraction and Transcription/OCR
        logger.info("Executing transcription/OCR stage...")
        mime_type = file.content_type or "application/octet-stream"
        transcript = transcriber.transcribe(temp_file_path, mime_type)
        logger.info(f"Successfully processed transcript. Length: {len(transcript)} characters.")

        # Handle empty transcript fallback gracefully
        if not transcript.strip():
            logger.warning("Extracted transcript content is empty.")
            # Set default minimal content to prevent pipeline crash
            transcript = "[Empty Content]"

        # 2. Pipeline Stage: Multi-Model Ensemble Scoring
        logger.info("Executing multi-model ensemble scoring...")
        ensemble_res = predict_ensemble(transcript)
        scam_score = ensemble_res["final_score"]
        # Instrumentation only: preserve the untouched ensemble output for trace logging,
        # since scam_score itself may be overwritten by Stage B/C below.
        raw_final_score = scam_score
        language = ensemble_res["language"]
        # Instrumentation only: capture per-component scores already present in
        # ensemble_res, previously discarded after this point. Not used in any
        # calculation below — read-only for trace logging.
        bart_score = ensemble_res["bart_score"]
        xlm_score = ensemble_res["xlm_score"]
        xgb_score = ensemble_res["xgb_score"]
        emb_score = ensemble_res["emb_score"]

        # 3. Pipeline Stage: Signal Dimension Detection
        logger.info("Executing signal pattern verification...")
        signals_res = signal_detector.detect_signals(transcript)

        # Calculate count of triggered signals
        signals_triggered = sum(1 for s in signals_res.values() if s["triggered"])

        # 4. Pipeline Stage: Reusable BART 2-Line Summary Generation
        logger.info("Executing summary generation stage...")
        summary = summarizer.generate_summary(transcript)

        # 5. Pipeline Stage: Final Verdict Classification Map
        # - scam_score >= 0.75 -> SCAM (HIGH confidence)
        # - scam_score between 0.50 - 0.74 -> SUSPICIOUS (MEDIUM confidence)
        # - scam_score < 0.50 -> SAFE (LOW confidence)
        if scam_score >= 0.75:
            verdict = "SCAM"
            confidence_band = "HIGH"
        elif scam_score >= 0.48:
            verdict = "SUSPICIOUS"
            confidence_band = "MEDIUM"
        else:
            verdict = "SAFE"
            confidence_band = "LOW"

        # Instrumentation only: record Stage A's verdict and prepare override flags
        # before Stage B/C run, so the trace log can show what each stage did.
        stage_a_verdict = verdict
        stage_b_overrode = False
        stage_c_overrode = False
        stage_c_rule_fired = None

        if signals_triggered >= 3:
            verdict = "SCAM"
            confidence_band = "HIGH"
            scam_score = max(scam_score, 0.85)
            stage_b_overrode = True
        elif signals_triggered >= 2 and signals_res.get("fake_rewards", {}).get("triggered"):
            verdict = "SCAM"
            confidence_band = "HIGH"
            scam_score = max(scam_score, 0.82)
            stage_b_overrode = True
        elif signals_triggered >= 2 and scam_score >= 0.52:
            verdict = "SCAM"
            confidence_band = "HIGH"
            scam_score = max(scam_score, 0.80)
            stage_b_overrode = True
        elif signals_triggered >= 1 and scam_score >= 0.65:
            verdict = "SCAM"
            confidence_band = "HIGH"
            scam_score = max(scam_score, 0.80)
            stage_b_overrode = True
        else:
    # Rule engine — catch specific high-confidence scam patterns
            _t = transcript.lower()

            investment_scam = (
                any(p in _t for p in [
                    "guaranteed", "assured returns", "guaranteed returns",
                    "30 percent", "daily profit", "monthly returns",
                    "risk free", "double your money"
                ]) and
                any(p in _t for p in [
                    "transfer", "invest", "deposit", "send", "pay"
                ])
            )

            job_fee_scam = (
                any(p in _t for p in [
                    "work from home", "part time", "earn daily",
                    "daily payment", "simple tasks", "earn 2000",
                    "earn 5000", "guaranteed salary"
                ]) and
                any(p in _t for p in [
                    "fee", "membership", "registration", "deposit",
                    "pay to", "pay first", "charges"
                ])
            )

            prize_fee_scam = (
                any(p in _t for p in [
                    "you have won", "lucky draw", "lottery", "prize",
                    "selected as winner", "congratulations"
                ]) and
                any(p in _t for p in [
                    "processing fee", "gst", "tax", "claim fee",
                    "to receive", "to claim", "release fee"
                ])
            )

            romance_scam = (
                any(p in _t for p in [
                    "crypto platform", "trading app", "investment app",
                    "i made profit", "made 3 lakh", "help you invest"
                ]) and
                any(p in _t for p in [
                    "upi pin", "share your", "confidential",
                    "don't tell", "don't share"
                ])
            )
            blackmail_scam = (
                any(p in _t for p in [
                    "video call recording", "recording of your", "send it to your employer",
                    "send it to your family", "share with your contacts", "destroy your reputation"
                ]) and
                any(p in _t for p in [
                    "pay", "transfer", "bitcoin", "rupees", "rupaye", "deposit"
                ])
            )
            reverse_otp_scam = (
                any(p in _t for p in [
                    "otp we just sent", "otp aane par share", "share the otp we",
                    "share that otp", "an otp will be sent", "verify your bank account",
                    "verify your aadhaar number"
                ]) and
                any(p in _t for p in [
                    "refund", "subsidy", "package", "customs", "claim"
                ])
            )

            ponzi_no_threat = (
                any(p in _t for p in [
                    "daily return", "daily profit", "trading signal", "made profit",
                    "guaranteed return", "% return", "percent return"
                ]) and
                any(p in _t for p in [
                    "invest", "deposit", "transfer", "wallet", "join"
                ])
            )



            if investment_scam or job_fee_scam or prize_fee_scam or romance_scam or blackmail_scam or reverse_otp_scam or ponzi_no_threat:
                verdict = "SCAM" if signals_triggered >= 1 else "SUSPICIOUS"
                confidence_band = "HIGH" if signals_triggered >= 1 else "MEDIUM"
                scam_score = max(scam_score, 0.82 if signals_triggered >= 1 else 0.55)
                # Instrumentation only: record which specific rule(s) fired and flag the override
                stage_c_overrode = True
                _stage_c_rule_map = {
                    "investment_scam": investment_scam,
                    "job_fee_scam": job_fee_scam,
                    "prize_fee_scam": prize_fee_scam,
                    "romance_scam": romance_scam,
                    "blackmail_scam": blackmail_scam,
                    "reverse_otp_scam": reverse_otp_scam,
                    "ponzi_no_threat": ponzi_no_threat,
                }
                stage_c_rule_fired = [name for name, fired in _stage_c_rule_map.items() if fired]
        

        # Instrumentation only: structured trace of the full decision path for offline analysis.
        # Does not affect verdict, scam_score, or the API response in any way.
        decision_trace = {
            "file_name": file.filename,
            "bart_score": round(bart_score, 4),
            "xlm_score": round(xlm_score, 4),
            "xgb_score": round(xgb_score, 4),
            "emb_score": round(emb_score, 4),
            "final_score": round(raw_final_score, 4),
            "raw_final_score": round(raw_final_score, 4),
            "language": language,
            "stage_a_verdict": stage_a_verdict,
            "stage_b_overrode": stage_b_overrode,
            "stage_c_overrode": stage_c_overrode,
            "stage_c_rule_fired": stage_c_rule_fired,
            "signals_triggered": signals_triggered,
            "final_verdict": verdict,
            "final_scam_score": round(scam_score, 4),
            "confidence_band": confidence_band,
        }
        logger.info(f"DECISION_TRACE {json.dumps(decision_trace)}")

        # Construct mapped Signal objects compliant with JSON schema
        signals_map = SignalsBreakdown(
            demand=SignalDetail(**signals_res["demand"]),
            urgency=SignalDetail(**signals_res["urgency"]),
            threat=SignalDetail(**signals_res["threat"]),
            manipulation=SignalDetail(**signals_res["manipulation"]),
            share_screen=SignalDetail(**signals_res["share_screen"]),
            personal_info=SignalDetail(**signals_res["personal_info"]),
            fake_rewards =SignalDetail(**signals_res["fake_rewards"])
        )


        processing_time_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(
            f"File processing complete. File: {file.filename}, "
            f"Processing Time: {processing_time_ms}ms, Verdict: {verdict}, "
            f"Score: {scam_score:.4f}"
        )

        return ScamDetectionResponse(
            scam_score=round(scam_score, 2),
            verdict=verdict,
            confidence_band=confidence_band,
            signals=signals_map,
            signals_triggered=signals_triggered,
            summary=summary,
            language=language,
            transcript=transcript,
            mode="file",
            processing_time_ms=processing_time_ms
        )

    except Exception as e:
        logger.error(f"Failed to process file upload endpoint: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Internal scanning engine failure: {str(e)}"
        )

    finally:
        # Enforce cleaning of file descriptors and temporary files on disk
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
                logger.info("Temporary analysis files successfully purged from disk.")
            except Exception as err:
                logger.warning(f"Failed to delete temp file {temp_file_path}: {err}")