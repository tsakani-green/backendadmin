# Convenience top-level Dockerfile for Render
# Render often expects a Dockerfile at the repository root. This file
# copies the actual application from ./app/ and builds it — keeping
# the single-source Dockerfile inside `app/` as the canonical source.

FROM python:3.11-slim

WORKDIR /app

# Install minimal system deps required by some Python packages
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first (better cache behavior)
COPY ./app/requirements.txt ./requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code from the app/ subfolder into the image
COPY ./app/ .

# Ensure uploads directory exists
RUN mkdir -p uploads

EXPOSE 8002

# Run the FastAPI app (same as the app/Dockerfile)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002", "--reload"]
