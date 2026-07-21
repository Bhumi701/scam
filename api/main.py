import time
import logging
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from api import routes_file, routes_realtime
from core.session_manager import session_manager

# Configure logging structure
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("scam_detector.api.main")


async def session_purger():
    """
    Asynchronous loop that executes every 10 minutes to auto-clean idle real-time sessions.
    """
    while True:
        try:
            await asyncio.sleep(600)  # Sleep for 10 minutes
            logger.info("Running periodic background check for inactive real-time sessions...")
            session_manager.cleanup_inactive_sessions(max_idle_seconds=1800)
        except asyncio.CancelledError:
            logger.info("Background session purger loop stopped.")
            break
        except Exception as e:
            logger.error(f"Error encountered in background session purger: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifecycle context manager.
    Handles system startup warmup of deep learning models on CPU and schedules session cleanup.
    """
    logger.info("Starting up scam-detector API and warming up CPU-based inference engines...")
    
    # Warm up models sequentially to avoid multiple download collisions and preload singletons
    try:
        from core.transcriber import get_whisper_model
        from core.ensemble import get_bart_pipeline, get_xlm_pipeline, get_xgb_components

        logger.info("[1/5] Pre-loading Whisper Tiny model on CPU...")
        get_whisper_model()

        logger.info("[2/5] Pre-loading BART Zero-Shot classifier on CPU...")
        get_bart_pipeline()

        logger.info("[3/5] Pre-loading XLM-RoBERTa text classifier on CPU...")
        get_xlm_pipeline()

        logger.info("[4/5] Loading and verifying XGBoost model components...")
        get_xgb_components()

        logger.info("[5/5] Pre-loading MiniLM sentence embeddings model...")
        from core.embeddings_scorer import get_embeddings_model, score_transcript as _warmup_emb
        get_embeddings_model()
        _warmup_emb("test warmup")
        logger.info("MiniLM embeddings model loaded and phrase clusters encoded.")

        logger.info("All ML models successfully warmed up and cached on CPU memory.")

        
    except Exception as e:
        logger.error(f"Inference engines warmup failed: {e}. Lazy loading will be used.", exc_info=True)

    # Spawn session purging daemon task
    purger_task = asyncio.create_task(session_purger())
    
    yield
    
    # Clean up and cancel daemon task during shutdown sequence
    logger.info("Initiating system shutdown sequences...")
    purger_task.cancel()
    await asyncio.gather(purger_task, return_exceptions=True)
    logger.info("Scam-detector API system shutdown complete.")


# Initialize FastAPI Instance
app = FastAPI(
    title="scam-detector",
    description="Multilingual (Hindi, English, Hinglish) Scam Call and Text Detection API Layer running fully on CPU.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS configurations for web client integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global Middleware for basic HTTP logging and latency calculation
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.perf_counter()
    logger.info(f"Incoming Request -> Method: {request.method} | Path: {request.url.path}")
    
    try:
        response = await call_next(request)
        process_time_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(
            f"Response -> Method: {request.method} | Path: {request.url.path} | "
            f"Status Code: {response.status_code} | Process Time: {process_time_ms}ms"
        )
        return response
    except Exception as e:
        process_time_ms = int((time.perf_counter() - start_time) * 1000)
        logger.error(
            f"Request Failed -> Method: {request.method} | Path: {request.url.path} | "
            f"Error: {str(e)} | Time: {process_time_ms}ms", 
            exc_info=True
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": f"Internal system execution error: {str(e)}"}
        )


# Global Exception Handler for Unhandled Exceptions
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled system exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "A critical server error occurred. Please contact system administrators."}
    )


# Register APIRouters with standard API Version prefixes
app.include_router(routes_file.router, prefix="/detect", tags=["File-Mode Processing"])
app.include_router(routes_realtime.router, prefix="/detect", tags=["Real-Time Processing"])


@app.get("/", tags=["Health Check"])
async def health_check():
    """
    Returns system status, active session stats, and general execution parameters.
    """
    # Quick session counts
    try:
        from core.session_manager import session_manager
        active_sessions_count = len(session_manager._sessions)
    except Exception:
        active_sessions_count = 0

    return {
        "status": "online",
        "system": "scam-detector",
        "processor": "CPU-only",
        "active_realtime_sessions": active_sessions_count,
        "supported_languages": ["English", "Hindi", "Hinglish"],
        "supported_modes": ["file (text/audio/video/image)", "realtime (audio stream chunking)"]
    }


if __name__ == "__main__":
    import uvicorn
    # Standard fallback script run parameters
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)