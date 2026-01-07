FROM rust:1.85.0 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/raiko-agent

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -u 10001 -m -s /usr/sbin/nologin raiko

RUN mkdir -p /etc/raiko-agent /var/lib/raiko-agent && chown -R raiko:raiko /var/lib/raiko-agent

COPY --from=builder /opt/raiko-agent/target/release/raiko-agent /usr/local/bin/raiko-agent
COPY config/boundless_config_docker.json /etc/raiko-agent/config.json

ENV RUST_LOG=info
ENV SQLITE_DB_PATH=/var/lib/raiko-agent/proof_requests.db

EXPOSE 9999

USER raiko

CMD ["/usr/local/bin/raiko-agent", "--address", "0.0.0.0", "--port", "9999", "--config-file", "/etc/raiko-agent/config.json"]
