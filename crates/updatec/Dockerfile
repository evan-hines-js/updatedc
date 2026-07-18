FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p updatec && \
    cp /src/target/release/updatec /tmp/updatec

FROM debian:bookworm-slim
RUN useradd --uid 65532 --create-home updated
COPY --from=build /tmp/updatec /usr/local/bin/updatec
USER 65532
ENTRYPOINT ["/usr/local/bin/updatec"]
