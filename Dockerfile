# Dockerfile for the Streamlit Scam Detector app
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

ENV PORT=8501
EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]
