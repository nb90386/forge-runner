ARG BASE
FROM --platform=linux/arm64 ${BASE} AS python
# A fresh config avoids inheriting PYTHON_VERSION, GPG_KEY, CMD or volumes.
# No RUN, package installation, downloaded code, or host files.
FROM scratch
COPY --from=python / /
ENV PATH=/usr/local/bin:/usr/bin:/bin
USER 65534:65534
WORKDIR /workspace
