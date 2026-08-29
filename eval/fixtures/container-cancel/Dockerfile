ARG NODE_IMAGE=node:22-bookworm-slim
FROM ${NODE_IMAGE}

COPY codex-fixture.mjs /usr/local/bin/codex
RUN chmod 0755 /usr/local/bin/codex

WORKDIR /workspace
ENTRYPOINT []
CMD ["codex", "--version"]
