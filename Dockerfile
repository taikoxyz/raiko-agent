FROM rust:1.85.0 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/boundless-agent

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -u 10001 -m -s /usr/sbin/nologin boundless

RUN mkdir -p /etc/boundless /var/lib/boundless && chown -R boundless:boundless /var/lib/boundless

COPY --from=builder /opt/boundless-agent/target/release/boundless-agent /usr/local/bin/boundless-agent
COPY config/boundless_config_docker.json /etc/boundless/config.json

ENV RUST_LOG=info
ENV SQLITE_DB_PATH=/var/lib/boundless/boundless_requests.db

EXPOSE 9999

USER boundless

CMD ["/usr/local/bin/boundless-agent", "--address", "0.0.0.0", "--port", "9999", "--config-file", "/etc/boundless/config.json"]
