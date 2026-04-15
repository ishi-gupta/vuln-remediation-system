# ──────────────────────────────────────────────────────────────
# Vulnerability Remediation System — all-in-one image
# Includes: scanner tools, issue creator, orchestrator, dashboard
# ──────────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="ishi-gupta"
LABEL description="Event-driven vulnerability remediation system with Devin AI"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Gitleaks (secret detection)
ARG GITLEAKS_VERSION=8.18.4
RUN curl -sSfL \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

WORKDIR /app

# Install Python dependencies (layer-cached)
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[scanners]" 2>/dev/null || \
    pip install --no-cache-dir \
        requests>=2.31.0 \
        fastapi>=0.111.0 \
        uvicorn>=0.30.0 \
        bandit>=1.7.0 \
        semgrep>=1.0.0 \
        pip-audit>=2.7.0

# Copy application code
COPY automation/ automation/
COPY dashboard/dist/ dashboard/dist/
COPY data/ data/
COPY tests/ tests/
COPY pyproject.toml .

# Re-install in editable mode with full source
RUN pip install --no-cache-dir -e ".[scanners]"

# Create data directory (state persistence)
RUN mkdir -p /app/data/reports

EXPOSE 8000

# Default: run the dashboard
CMD ["uvicorn", "automation.dashboard:app", "--host", "0.0.0.0", "--port", "8000"]
