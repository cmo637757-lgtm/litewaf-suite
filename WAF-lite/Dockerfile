FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    WORK_DIR=/tmp/litewaf-nginx-check \
    VOLUME_PREFIX=/tmp/litewaf-nginx-volume \
    RELOAD_PREFIX=/tmp/litewaf-nginx-reload \
    SOAK_PREFIX=/tmp/litewaf-nginx-soak

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apache2-utils \
        build-essential \
        ca-certificates \
        curl \
        libpcre2-dev \
        libssl-dev \
        python3 \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /waf-lite
COPY . .

RUN bash scripts/prepare_nginx_env.sh \
    && make -C "$WORK_DIR/nginx-1.31.1" -j2 \
    && make clean \
    && make test

CMD ["bash", "scripts/run_final_acceptance.sh"]
