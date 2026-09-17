# Reproducibility only: the Covenant proxy itself is meant to run on the
# HOST, launched by Claude Desktop / Gemini CLI as a local stdio subprocess.
# This image exists so judges/CI can run the test suite and the scripted
# demo without installing Python or Claude Desktop locally -- see
# compose.yaml for the two ways this image is actually used.
FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src
COPY demo ./demo
COPY tests ./tests
COPY scripts ./scripts

RUN pip install --no-cache-dir -e ".[dev]"

CMD ["pytest", "-q"]
