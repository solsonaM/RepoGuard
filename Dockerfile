FROM python:3.13-slim
ARG SEMGREP_VERSION=">=1.98,<2"
ARG GITLEAKS_VERSION="8.30.1"
ARG OSV_SCANNER_VERSION="v2.6.0"

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git yara file strace && rm -rf /var/lib/apt/lists/*
RUN python -m pip install --no-cache-dir "semgrep${SEMGREP_VERSION}"
RUN curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -o /tmp/gitleaks.tgz && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks && rm /tmp/gitleaks.tgz
RUN curl -fsSL "https://github.com/google/osv-scanner/releases/download/${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" -o /usr/local/bin/osv-scanner && chmod +x /usr/local/bin/osv-scanner

WORKDIR /scanner
COPY app /scanner/app
COPY rules /scanner/rules
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python","-m","app.cli"]
