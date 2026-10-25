FROM docker.io/library/alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS alpine-base

FROM alpine-base AS downloads
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
ARG OPENTOFU_VERSION=1.13.1
ARG OPENTOFU_SHA256_AMD64=378ada19d4bc70c43732004e8159be771b23b9a5afdf059e5f8a2b3fa2c70a69
RUN apk add --no-cache ca-certificates=20261020-r0 curl=8.23.0-r0
WORKDIR /download
RUN test "$(uname -m)" = x86_64 \
    && archive="tofu_${OPENTOFU_VERSION}_linux_amd64.tar.gz" \
    && curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
      --output "${archive}" \
      "https://github.com/opentofu/opentofu/releases/download/v${OPENTOFU_VERSION}/${archive}" \
    && echo "${OPENTOFU_SHA256_AMD64}  ${archive}" | sha256sum -c - \
    && tar -xzf "${archive}" tofu \
    && install -D -m 0755 tofu /out/usr/local/bin/tofu

FROM alpine-base AS python-env
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
ARG PYTHON_VERSION=3.12.13
ENV UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_PYTHON_DOWNLOADS=manual \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1
RUN apk add --no-cache ca-certificates=20261020-r0 uv=0.11.19-r1
COPY toolbox/pyproject.toml toolbox/uv.lock /toolbox/
RUN uv export --directory /toolbox --frozen --no-emit-project --no-header --no-annotate \
        --format requirements-txt --output-file /tmp/requirements.txt \
    && uv python install "${PYTHON_VERSION}" \
    && uv venv --python "${PYTHON_VERSION}" /opt/venv \
    && uv pip install --python /opt/venv/bin/python --require-hashes --no-deps --only-binary :all: \
        --compile-bytecode --requirement /tmp/requirements.txt \
    && chmod -R u=rwX,g=rX,o=rX /opt/python /opt/venv

FROM alpine-base AS runtime-base
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
RUN apk add --no-cache \
      actionlint=1.7.12-r3 \
      bash=5.3.9-r1 \
      ca-certificates=20261020-r0 \
      git=2.54.0-r0 \
      jq=1.8.2-r0 \
      make=4.4.1-r4 \
      nodejs=24.22.1-r0 \
      openssh-client-default=10.3_p1-r1 \
      shellcheck=0.11.0-r1 \
      uv=0.11.19-r1 \
    && addgroup -g 10001 toolbox \
    && adduser -D -u 10001 -G toolbox -h /home/toolbox -s /bin/bash toolbox \
    && install -d -o toolbox -g toolbox -m 0755 /work \
    && install -d -o toolbox -g toolbox -m 0700 /home/toolbox \
    && find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec chmod ug-s {} + \
    && rm -rf /var/cache/apk/* /etc/apk/cache

FROM runtime-base AS toolbox
ARG IMAGE_VERSION=0.0.0-dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="linux-compliance-runner" \
      org.opencontainers.image.description="CI toolbox for the freesecdev.linux_compliance collection; not a self-hosted runner" \
      org.opencontainers.image.source="https://github.com/FreeSecDev/linux-compliance-runner" \
      org.opencontainers.image.url="https://github.com/FreeSecDev/linux-compliance-runner" \
      org.opencontainers.image.documentation="https://github.com/FreeSecDev/linux-compliance-runner/blob/main/docs/image.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="FreeSecDev" \
      org.opencontainers.image.base.name="docker.io/library/alpine:3.24" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"
COPY --from=downloads /out/usr/local/bin/tofu /usr/local/bin/tofu
COPY --from=python-env /opt/python /opt/python
COPY --from=python-env /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin \
    HOME=/home/toolbox \
    LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_PYTHON_DOWNLOADS=never \
    UV_CACHE_DIR=/tmp/.cache/uv \
    XDG_CACHE_HOME=/tmp/.cache \
    PRE_COMMIT_HOME=/tmp/.cache/pre-commit \
    ANSIBLE_HOME=/tmp/.ansible \
    ANSIBLE_LOCAL_TEMP=/tmp/.ansible/tmp \
    PYRIGHT_PYTHON_GLOBAL_NODE=1 \
    PYRIGHT_PYTHON_IGNORE_WARNINGS=1 \
    CHECKOV_DISABLE_TELEMETRY=1
USER 10001:10001
WORKDIR /work
CMD ["/bin/bash"]
