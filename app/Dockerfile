FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && apt-get install -y gcc g++ && rm -rf /var/lib/apt/lists/*

# install deps
COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# copy the *package* into /app/app
COPY app /app/app

# optional runtime dir
RUN mkdir -p /app/uploads

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port $PORT"]
