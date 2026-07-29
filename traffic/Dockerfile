FROM python:3.13-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        bash \
        gcc \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy traffic package into /app/traffic
COPY . ./traffic

ENV PYTHONUNBUFFERED=1

CMD ["python3", "-m", "traffic.orchestrator", "--mode", "all"]
