FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# requirements.txt is at repo root
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# copy the Python package folder into the image as /app/app
COPY app/ ./app/

# optional if you need uploads at runtime
RUN mkdir -p uploads

EXPOSE 8000

# IMPORTANT: use Render's PORT if set
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
