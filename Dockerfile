FROM python:3.12-slim

# integrity-sdk is a git dependency (pyproject.toml) -- git must be present to resolve it.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY shield ./shield
COPY scripts ./scripts
RUN pip install --no-cache-dir .

ENTRYPOINT ["shield", "run"]
CMD []
