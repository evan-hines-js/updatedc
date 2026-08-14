FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p updatec && \
    cp /src/target/release/updatec /tmp/updatec

FROM debian:bookworm-slim
# The system trust store, which every outbound HTTPS client this binary builds needs — the alert
# webhook and the subscription delivery. Its absence is not a per-request failure: the TLS backend
# loads the platform verifier when the CLIENT is constructed, so a controller configured with
# `UPDATED_ALERT_URL` refused to start at all, and a repository with a subscription failed every
# delivery, both with an error naming neither certificates nor this image.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && useradd --uid 65532 --create-home updated
COPY --from=build /tmp/updatec /usr/local/bin/updatec
USER 65532
ENTRYPOINT ["/usr/local/bin/updatec"]
