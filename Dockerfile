FROM python:3.12-slim

# integrity-sdk is a git dependency (pyproject.toml) -- git must be present to resolve it.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# pyproject.toml pins integrity-sdk via the absolute host path
# file:///home/xibalba/Projects/integrity-core/integrity-sdk (see that file's own comment:
# reproducible only on a machine with integrity-core checked out at that exact path). Built with
# docker-compose.yml's context widened to the shared parent of both repos, this recreates that
# same absolute path inside the image rather than editing the dependency URL, so a local
# (non-Docker) editable install of this package is unaffected by anything in this file.
COPY integrity-core/integrity-sdk /home/xibalba/Projects/integrity-core/integrity-sdk

WORKDIR /app

COPY xibalba-shield/pyproject.toml xibalba-shield/README.md xibalba-shield/LICENSE ./
COPY xibalba-shield/shield ./shield
COPY xibalba-shield/scripts ./scripts
RUN pip install --no-cache-dir .

ENTRYPOINT ["shield", "run"]
CMD []
