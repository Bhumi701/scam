import os
import tempfile
import logging
from typing import Optional
from PIL import Image
import pytesseract
import librosa
import numpy as np

# Configure logger
logger = logging.getLogger("scam_detector.transcriber")
logging.basicConfig(level=logging.INFO)

# Lazy-loaded singletons
_whisper_model = None

def get_whisper_model():
    """
    Lazily loads and returns the Whisper Tiny model on CPU.
    """
    global _whisper_model
    if _whisper_model is None:
        logger.info("Initializing Whisper Tiny model on CPU...")
        import whisper
        # Force CPU execution as required by system specifications
        _whisper_model = whisper.load_model("tiny", device="cpu")
        logger.info("Whisper Tiny model successfully loaded on CPU.")
    return _whisper_model


class Transcriber:
    def __init__(self):
        pass

    def transcribe(self, file_path: str, mime_type: str) -> str:
        """
        Transcribes or extracts text from the provided file path based on its MIME type.
        Supports text, audio, video, and image inputs.
        """
        logger.info(f"Processing file: {file_path} with MIME type: {mime_type}")
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Input file not found at: {file_path}")

        mime_type = mime_type.lower()

        if mime_type.startswith("text/"):
            return self._read_text_file(file_path)
        elif mime_type.startswith("audio/"):
            return self._transcribe_audio(file_path)
        elif mime_type.startswith("video/"):
            return self._transcribe_video(file_path)
        elif mime_type.startswith("image/"):
            return self._ocr_image(file_path)
        else:
            # Fallback based on extension matching if MIME type is generic/octet-stream
            return self._fallback_processing(file_path)

    def _read_text_file(self, file_path: str) -> str:
        logger.info("Reading text input file...")
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except UnicodeDecodeError:
            # Fallback to latin-1 if utf-8 fails
            with open(file_path, "r", encoding="latin-1") as f:
                return f.read().strip()

    def _transcribe_audio(self, audio_path: str) -> str:
        logger.info("Loading audio with librosa for resampling...")
        try:
            # Load audio at 16000Hz mono (standard sample rate expected by Whisper)
            y, sr = librosa.load(audio_path, sr=16000, mono=True)
        except Exception as e:
            logger.error(f"librosa failed to load audio: {str(e)}")
            raise RuntimeError(f"Failed to process audio file: {str(e)}")

        logger.info("Transcribing audio using Whisper Tiny on CPU...")
        model = get_whisper_model()
        
        # Whisper can accept a pre-loaded numpy float array directly
        try:
            result = model.transcribe(y, fp16=False)
            transcript = result.get("text", "").strip()
            logger.info("Audio transcription completed successfully.")
            return transcript
        except Exception as e:
            logger.error(f"Whisper transcription failed: {str(e)}")
            raise RuntimeError(f"Whisper processing error: {str(e)}")

    def _transcribe_video(self, video_path: str) -> str:
        logger.info("Extracting audio from video file using moviepy...")
        from moviepy.editor import VideoFileClip

        temp_audio_fd, temp_audio_path = tempfile.mkstemp(suffix=".wav")
        os.close(temp_audio_fd)

        try:
            video = VideoFileClip(video_path)
            if video.audio is None:
                raise ValueError("The provided video file does not contain any audio track.")
            
            # Write audio track to temporary WAV file
            logger.info(f"Writing temporary audio track to {temp_audio_path}")
            video.audio.write_audiofile(
                temp_audio_path,
                fps=16000,
                nbytes=2,
                codec="pcm_s16le",
                verbose=False,
                logger=None
            )
            video.close()

            # Transcribe the extracted audio file using the standard audio processor
            transcript = self._transcribe_audio(temp_audio_path)
            return transcript
        except Exception as e:
            logger.error(f"Video audio extraction or transcription failed: {str(e)}")
            raise RuntimeError(f"Failed to extract or transcribe video audio: {str(e)}")
        finally:
            if os.path.exists(temp_audio_path):
                try:
                    os.remove(temp_audio_path)
                except Exception as cleanup_err:
                    logger.warning(f"Failed to delete temp audio file {temp_audio_path}: {cleanup_err}")

    def _ocr_image(self, image_path: str) -> str:
        logger.info("Performing OCR on image via pytesseract...")
        try:
            img = Image.open(image_path)
            # Standard Hindi + English configuration if available. Fallback to English on error.
            try:
                text = pytesseract.image_to_string(img, lang="eng+hin")
            except Exception as lang_err:
                logger.warning(f"Multi-language OCR failed, falling back to English: {lang_err}")
                text = pytesseract.image_to_string(img, lang="eng")
            
            extracted_text = text.strip()
            logger.info("Image OCR extraction completed.")
            return extracted_text
        except Exception as e:
            logger.error(f"pytesseract OCR execution failed: {str(e)}")
            raise RuntimeError(f"Failed to perform OCR on image: {str(e)}")

    def _fallback_processing(self, file_path: str) -> str:
        _, ext = os.path.splitext(file_path.lower())
        logger.warning(f"Unknown or generic MIME type. Performing fallback check by extension: {ext}")
        
        audio_exts = {".wav", ".mp3", ".m4a", ".flac", ".ogg", ".aac"}
        video_exts = {".mp4", ".mkv", ".avi", ".mov", ".flv", ".webm"}
        image_exts = {".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp"}
        text_exts = {".txt", ".csv", ".json", ".log"}

        if ext in text_exts:
            return self._read_text_file(file_path)
        elif ext in audio_exts:
            return self._transcribe_audio(file_path)
        elif ext in video_exts:
            return self._transcribe_video(file_path)
        elif ext in image_exts:
            return self._ocr_image(file_path)
        else:
            raise ValueError(f"Unsupported file format extension: {ext}")