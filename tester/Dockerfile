FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Core packages + security tools available in apt
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip curl wget git \
    nmap nikto gobuster wfuzz \
    dnsutils whois openssl netcat-openbsd \
    iputils-ping net-tools \
    libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install tools not in apt
# ffuf
RUN wget -q https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
    -O /tmp/ffuf.tar.gz && \
    tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf && \
    rm /tmp/ffuf.tar.gz

# nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.9/nuclei_3.2.9_linux_amd64.zip \
    -O /tmp/nuclei.zip && \
    apt-get install -y unzip && unzip -q /tmp/nuclei.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && rm /tmp/nuclei.zip

# subfinder
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip \
    -O /tmp/sf.zip && \
    unzip -q /tmp/sf.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder && rm /tmp/sf.zip

# Python tool execution API
WORKDIR /app
COPY tester/requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt
COPY tester/app.py /app/app.py

EXPOSE 8001
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8001"]
