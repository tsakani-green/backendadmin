FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc g++ && rm -rf /var/lib/apt/lists/*

# install deps
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# put code under /app/app  (so "app" becomes a package)
COPY app/ ./app

RUN mkdir -p uploads

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port $PORT"]
