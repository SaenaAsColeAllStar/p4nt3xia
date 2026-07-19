FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GOPATH=/go \
    PATH="/go/bin:/usr/local/go/bin:${PATH}" \
    P4NT3XIA_FFUF_WORDLIST=/app/tools/wordlists/common.txt

WORKDIR /app

# System deps + nmap + whatweb (ruby)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    ca-certificates \
    nmap \
    ruby \
    ruby-dev \
    libxslt1-dev \
    libxml2-dev \
    zlib1g-dev \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# WhatWeb (Ruby CLI from upstream)
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/WhatWeb \
    && ln -sf /opt/WhatWeb/whatweb /usr/local/bin/whatweb \
    && chmod +x /opt/WhatWeb/whatweb \
    && (gem install addressable --no-document || true)

# Install Go (for ProjectDiscovery tools)
ARG GO_VERSION=1.22.10
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz \
    && tar -C /usr/local -xzf /tmp/go.tgz \
    && rm /tmp/go.tgz

# ProjectDiscovery + ffuf tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/ffuf/ffuf/v2@latest \
    && nuclei -update-templates || true

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY tools ./tools

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
