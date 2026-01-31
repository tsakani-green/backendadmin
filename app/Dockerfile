FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# requirements is inside app/
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy the whole app package
COPY app ./app

RUN mkdir -p uploads

EXPOSE 10000

CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port $PORT"]
