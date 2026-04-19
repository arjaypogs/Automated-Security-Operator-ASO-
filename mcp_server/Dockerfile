FROM python:3.11-slim

WORKDIR /app

COPY mcp_server/requirements.txt /tmp/req.txt
RUN pip install --no-cache-dir -r /tmp/req.txt

COPY mcp_server/server.py /app/server.py

ENV PYTHONUNBUFFERED=1
EXPOSE 8002

CMD ["python", "server.py"]
