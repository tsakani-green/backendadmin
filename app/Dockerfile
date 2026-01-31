FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (this copies everything inside repo/app/ into /app)
COPY . .

# Create uploads directory
RUN mkdir -p uploads

# Render provides PORT env var. Expose is optional but fine.
EXPOSE 8000

# IMPORTANT: main.py is at /app/main.py, so use "main:app" (NOT app.main:app)
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
