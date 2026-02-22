FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directories for runtime
RUN mkdir -p /app/output /repo

# The target repo is mounted at /repo, output at /app/output
VOLUME ["/repo", "/app/output"]

ENTRYPOINT ["python", "main.py"]
CMD ["--repo-path", "/repo", "--output-dir", "/app/output"]
