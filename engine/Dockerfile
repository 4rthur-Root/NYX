FROM python:3.13-slim

WORKDIR /engine

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

# Copy engine source
COPY . .

# Default to bash; Makefile overrides with pytest commands
CMD ["/bin/bash"]
