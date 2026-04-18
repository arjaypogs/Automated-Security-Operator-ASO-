FROM python:3.11-slim

WORKDIR /app

# System packages needed by ASO tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git dnsutils whois openssl nmap \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY backend/requirements.txt /tmp/backend-req.txt
COPY requirements.txt /tmp/aso-req.txt
RUN pip install --no-cache-dir -r /tmp/aso-req.txt -r /tmp/backend-req.txt

# Copy ASO package and backend app
COPY aso/ /app/aso/
COPY main.py /app/main.py
COPY config.yaml /app/config.yaml
COPY backend/app/ /app/backend/app/

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
