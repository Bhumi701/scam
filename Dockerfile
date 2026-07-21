# Dockerfile for Hugging Face Spaces (Docker SDK, free CPU tier)
FROM python:3.11-slim

WORKDIR /app

# System deps some ML libs need (ffmpeg for Whisper audio, build tools for xgboost/sklearn)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project (core/, api/, config/, models/, etc.)
COPY . .

# HF Spaces routes traffic to port 7860 by default
ENV PORT=7860
EXPOSE 7860

# Adjust "api.main:app" if your actual entry point differs
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "7860"]
