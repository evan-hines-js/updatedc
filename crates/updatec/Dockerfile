# Red Hat UBI, build and runtime both.
#
# The two stages must share a libc. A binary linked against Debian bookworm's glibc 2.36 does not
# start on UBI 9 (glibc 2.34) — it fails with a missing GLIBC_2.35/2.36 symbol before `main` — so
# moving the runtime to UBI without moving the build is not a smaller change, it is a broken image.
FROM registry.access.redhat.com/ubi9/ubi@sha256:5426a8f45e80a07168a30ea24d84f266094b3756624a5508cc53927e6ee39e09 AS build

# `aws-lc-sys` builds its C sources with cmake, and `zstd-sys` and `ring` need a C compiler; perl is
# used by the crypto build's generators. UBI carries no toolchain by default, unlike the upstream
# `rust:` images this replaced.
COPY --chmod=0755 scripts/install-ubi-build-dependencies.sh /usr/local/bin/install-ubi-build-dependencies
RUN /usr/local/bin/install-ubi-build-dependencies

# The Rust version is NOT named here. `rustup` reads `rust-toolchain.toml` from the workspace and
# installs exactly the channel it pins, so this image tracks the repository's one toolchain
# declaration instead of being a third copy of "1.95" that CI, the toolchain file, and this
# Dockerfile could each drift from independently.
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --default-toolchain none --profile minimal

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .cargo ./.cargo
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p updatec -p server && \
    cp /src/target/release/updatec /tmp/updatec && \
    cp /src/target/release/server /tmp/server

FROM registry.access.redhat.com/ubi9/ubi-minimal@sha256:8eb2830d0936237fc13a1f2f7e45aecf90d69043380ad167fad0343632937f41
# No package installs. `ubi-minimal` already carries `ca-certificates`, which every outbound HTTPS
# client this binary builds needs — the alert webhook and the subscription delivery. Its absence is
# not a per-request failure: the TLS backend loads the platform verifier when the CLIENT is
# constructed, so a controller configured with `UPDATED_ALERT_URL` refused to start at all, and a
# repository with a subscription failed every delivery, both with an error naming neither
# certificates nor this image. Verified present rather than assumed, below.
RUN test -e /etc/pki/tls/certs/ca-bundle.crt && \
    useradd --uid 65532 --create-home updated
COPY --from=build /tmp/updatec /usr/local/bin/updatec
# `server` rides along solely so an operator can mint a repository's TUF signing keys
# (`server init`) without a Rust toolchain — otherwise the very first install step demands one.
# It is not an entrypoint; reach it with `docker run --entrypoint /usr/local/bin/server`.
COPY --from=build /tmp/server /usr/local/bin/server
USER 65532
ENTRYPOINT ["/usr/local/bin/updatec"]
