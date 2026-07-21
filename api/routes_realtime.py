import os
import time
import logging
import tempfile
from fastapi import APIRouter, File, UploadFile, Form, HTTPException
from api.schemas import (
    ScamDetectionResponse, 
    SessionStartResponse, 
    SessionStatusResponse, 
    SignalsBreakdown, 
    SignalDetail
)
from core.session_manager import session_manager
from core.transcriber import Transcriber
from core.ensemble import predict_ensemble
from core.signal_detector import SignalDetector
from core.summarizer import Summarizer

# Configure logger
logger = logging.getLogger("scam_detector.api.realtime")
logging.basicConfig(level=logging.INFO)

router = APIRouter()

# Initialize core processing component singletons
transcriber = Transcriber()
signal_detector = SignalDetector()
summarizer = Summarizer()


@router.post("/start", response_model=SessionStartResponse)
async def start_session():
    """
    Spawns a new in-memory real-time scam tracking session.
    """
    logger.info("Received request to start a real-time call tracking session.")
    try:
        session_id = session_manager.create_session()
        return SessionStartResponse(session_id=session_id, status="started")
    except Exception as e:
        logger.error(f"Failed to initialize real-time session: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to initialize scanning session.")


@router.post("/chunk", response_model=ScamDetectionResponse)
async def process_chunk(
    session_id: str = Form(..., description="Active session tracking ID"),
    chunk: UploadFile = File(..., description="Audio stream block file representing the latest call window")
):
    """
    Pushes an audio chunk into an active session. Transcribes, appends text,
    updates running score via leaky integrator, and returns intermediate status results.
    """
    logger.info(f"Received chunk upload. Session: {session_id}, Chunk File: {chunk.filename}")
    start_time = time.perf_counter()

    # Retrieve session state
    session = session_manager.get_session(session_id)
    if not session:
        logger.warning(f"Attempted chunk upload on missing/expired session: {session_id}")
        raise HTTPException(
            status_code=404,
            detail=f"Real-time session ID {session_id} not found or expired. Call /start to begin a new session."
        )

    temp_chunk_path = None
    try:
        # Save uploaded chunk to a secure temporary location
        suffix = os.path.splitext(chunk.filename)[1] if chunk.filename else ".wav"
        temp_fd, temp_chunk_path = tempfile.mkstemp(suffix=suffix)
        
        with os.fdopen(temp_fd, 'wb') as tmp:
            content = await chunk.read()
            tmp.write(content)

        # 1. Transcribe the new incoming audio chunk
        mime_type = chunk.content_type or "audio/wav"
        chunk_transcript = transcriber.transcribe(temp_chunk_path, mime_type)
        logger.info(f"Chunk transcription complete. Content: '{chunk_transcript}'")

        # 2. Append transcription to global session context under session lock
        with session.lock:
            if chunk_transcript.strip():
                if session.transcript:
                    session.transcript += " " + chunk_transcript.strip()
                else:
                    session.transcript = chunk_transcript.strip()
            
            # Keep a local snapshot for this pipeline pass
            current_full_transcript = session.transcript

        # 3. Score overall accumulated transcript and update session running score
        if current_full_transcript:
            # Get raw prediction metrics of the complete transcript
            ensemble_res = predict_ensemble(current_full_transcript)
            current_chunk_score = ensemble_res["final_score"]
            language = ensemble_res["language"]

            # Calculate the running score using standard leaky integrator accumulator:
            # new_score = (previous_score * 0.7) + (current_chunk_score * 0.3)
            running_score = session_manager.process_accumulated_score(session_id, current_chunk_score)

            # Evaluate signal dimension matching on full transcript so far
            signals_res = signal_detector.detect_signals(current_full_transcript)
            signals_triggered = sum(1 for s in signals_res.values() if s["triggered"])

            # Extract current 2-line summary
            summary = summarizer.generate_summary(current_full_transcript)
        else:
            # Fallback values if no transcript text has been captured yet
            running_score = 0.0
            language = "English"
            signals_triggered = 0
            summary = "Waiting for call stream conversation data..."
            signals_res = signal_detector.detect_signals("")

        # 4. Map running score to standard verdict thresholds
        if running_score >= 0.75:
            verdict = "SCAM"
            confidence_band = "HIGH"
        elif running_score >= 0.50:
            verdict = "SUSPICIOUS"
            confidence_band = "MEDIUM"
        else:
            verdict = "SAFE"
            confidence_band = "LOW"

        # Construct responsive schema models
        signals_map = SignalsBreakdown(
            demand=SignalDetail(**signals_res["demand"]),
            urgency=SignalDetail(**signals_res["urgency"]),
            threat=SignalDetail(**signals_res["threat"]),
            manipulation=SignalDetail(**signals_res["manipulation"]),
            share_screen=SignalDetail(**signals_res["share_screen"]),
            personal_info=SignalDetail(**signals_res["personal_info"])
        )

        processing_time_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(
            f"Chunk processed. Session: {session_id}, Score: {running_score:.4f}, "
            f"Verdict: {verdict}, Processing Time: {processing_time_ms}ms"
        )

        return ScamDetectionResponse(
            scam_score=round(running_score, 2),
            verdict=verdict,
            confidence_band=confidence_band,
            signals=signals_map,
            signals_triggered=signals_triggered,
            summary=summary,
            language=language,
            transcript=current_full_transcript,
            mode="realtime",
            processing_time_ms=processing_time_ms
        )

    except Exception as e:
        logger.error(f"Error processing real-time chunk for session {session_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Realtime analysis pipeline error: {str(e)}"
        )

    finally:
        # Purge temporary files
        if temp_chunk_path and os.path.exists(temp_chunk_path):
            try:
                os.remove(temp_chunk_path)
            except Exception as err:
                logger.warning(f"Failed to cleanup temp chunk file {temp_chunk_path}: {err}")


@router.get("/status/{session_id}", response_model=SessionStatusResponse)
async def get_session_status(session_id: str):
    """
    Returns the latest status parameters and scores without submitting new chunks.
    """
    logger.info(f"Status check request received for Session ID: {session_id}")
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=404,
            detail=f"Session with ID {session_id} not found."
        )

    with session.lock:
        running_score = session.running_score
        transcript = session.transcript

    # Map current states
    if running_score >= 0.75:
        verdict = "SCAM"
        confidence_band = "HIGH"
    elif running_score >= 0.50:
        verdict = "SUSPICIOUS"
        confidence_band = "MEDIUM"
    else:
        verdict = "SAFE"
        confidence_band = "LOW"

    # Evaluate current active signals
    signals_res = signal_detector.detect_signals(transcript)
    signals_triggered = sum(1 for s in signals_res.values() if s["triggered"])

    return SessionStatusResponse(
        session_id=session_id,
        scam_score=round(running_score, 2),
        verdict=verdict,
        confidence_band=confidence_band,
        signals_triggered=signals_triggered,
        transcript_so_far=transcript
    )


@router.post("/stop/{session_id}", response_model=ScamDetectionResponse)
async def stop_session(session_id: str):
    """
    Closes the real-time session, computes final composite indicators, 
    deletes it from in-memory registers, and returns the absolute final scam report.
    """
    logger.info(f"Stop and finalize call tracking request for Session ID: {session_id}")
    start_time = time.perf_counter()

    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=404,
            detail=f"Session with ID {session_id} not found."
        )

    try:
        with session.lock:
            final_transcript = session.transcript
            running_score = session.running_score

        # Generate final indicators using full history compiled during session lifetime
        if final_transcript:
            ensemble_res = predict_ensemble(final_transcript)
            language = ensemble_res["language"]
            
            # The running score has already been updated dynamically through chunks;
            # evaluate final signal flags and compile summaries on the absolute completed transcript.
            signals_res = signal_detector.detect_signals(final_transcript)
            signals_triggered = sum(1 for s in signals_res.values() if s["triggered"])
            summary = summarizer.generate_summary(final_transcript)
        else:
            language = "English"
            signals_triggered = 0
            summary = "Call stream closed with no transactional conversation registered."
            signals_res = signal_detector.detect_signals("")

        # Standard classifications mapping
        if running_score >= 0.75:
            verdict = "SCAM"
            confidence_band = "HIGH"
        elif running_score >= 0.50:
            verdict = "SUSPICIOUS"
            confidence_band = "MEDIUM"
        else:
            verdict = "SAFE"
            confidence_band = "LOW"

        signals_map = SignalsBreakdown(
            demand=SignalDetail(**signals_res["demand"]),
            urgency=SignalDetail(**signals_res["urgency"]),
            threat=SignalDetail(**signals_res["threat"]),
            manipulation=SignalDetail(**signals_res["manipulation"]),
            share_screen=SignalDetail(**signals_res["share_screen"]),
            personal_info=SignalDetail(**signals_res["personal_info"])
        )

        processing_time_ms = int((time.perf_counter() - start_time) * 1000)

        # Standard final unified response structure
        response = ScamDetectionResponse(
            scam_score=round(running_score, 2),
            verdict=verdict,
            confidence_band=confidence_band,
            signals=signals_map,
            signals_triggered=signals_triggered,
            summary=summary,
            language=language,
            transcript=final_transcript,
            mode="realtime",
            processing_time_ms=processing_time_ms
        )

        # Clear session strictly from memory
        session_manager.delete_session(session_id)
        logger.info(f"Session {session_id} closed, evaluated, and fully purged from RAM.")

        return response

    except Exception as e:
        logger.error(f"Failed to finalize/stop real-time session {session_id}: {e}", exc_info=True)
        # Ensure cleanup attempt anyway
        session_manager.delete_session(session_id)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to safely terminate tracking session: {str(e)}"
        )