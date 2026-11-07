FROM python:3.13.18-slim-bookworm@sha256:f3dac913ab53b78c64f26d5518fcd7043d5a1a46522d6a493b598c3ed12f62a6

WORKDIR /app
COPY requirements.txt .
RUN test -s /etc/ssl/certs/ca-certificates.crt \
    && python -m pip --isolated install --index-url https://pypi.org/simple --only-binary=:all: \
        --require-hashes --no-cache-dir -r requirements.txt \
    && python -m pip check

COPY transport.py server.py .
ARG BUILD_REVISION
RUN python -c 'import re, sys; sys.exit(0 if re.fullmatch(r"[0-9a-f]{40}", sys.argv[1]) else 1)' "$BUILD_REVISION" \
    && printf '%s\n' "$BUILD_REVISION" > revision
LABEL org.opencontainers.image.revision=$BUILD_REVISION
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "-B", "-E", "-s", "/app/server.py"]
