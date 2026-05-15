# Stage 1: Build React frontend
FROM node:22-slim AS frontend
WORKDIR /app
COPY waffleiron-web/package.json waffleiron-web/package-lock.json ./
RUN npm install --no-audit --no-fund
COPY waffleiron-web/ ./
RUN npm run build

# Stage 2: Python runtime
FROM python:3.12-slim AS runtime
RUN groupadd -r waffleiron && useradd -r -g waffleiron -d /app waffleiron
WORKDIR /app

# Install Python packages
COPY waffleiron/pyproject.toml waffleiron/
COPY waffleiron/src/ waffleiron/src/
RUN pip install --no-cache-dir ./waffleiron

COPY waffleiron-cli/pyproject.toml waffleiron-cli/
COPY waffleiron-cli/src/ waffleiron-cli/src/
RUN pip install --no-cache-dir ./waffleiron-cli

COPY waffleiron-api/pyproject.toml waffleiron-api/
COPY waffleiron-api/src/ waffleiron-api/src/
RUN pip install --no-cache-dir ./waffleiron-api

# Copy built frontend
COPY --from=frontend /app/dist /app/static

# Create default mount points for K8s secrets
RUN mkdir -p /certs /secrets

ENV STATIC_DIR=/app/static
ENV PORT=8080
EXPOSE 8080

USER waffleiron
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')"

CMD ["uvicorn", "waffleiron_api.main:app", "--host", "0.0.0.0", "--port", "8080"]
