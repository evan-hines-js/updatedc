# Red Hat UBI, build and runtime both — see `crates/updatec/Dockerfile` for why the two stages
# cannot be split across distributions: UBI 9 is glibc 2.34, and a bookworm-built binary will not
# start on it.
FROM registry.access.redhat.com/ubi9/ubi@sha256:5426a8f45e80a07168a30ea24d84f266094b3756624a5508cc53927e6ee39e09 AS build

# `aws-lc-sys` builds its C sources with cmake; `zstd-sys` and `ring` need a C compiler.
RUN dnf install -y --setopt=install_weak_deps=False gcc cmake make perl && dnf clean all

# The toolchain comes from the workspace's `rust-toolchain.toml`, never from a version named here.
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --default-toolchain none --profile minimal

WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p updated-healthproxy && \
    cp /src/target/release/updated-healthproxy /tmp/updated-healthproxy

FROM registry.access.redhat.com/ubi9/ubi-minimal@sha256:8eb2830d0936237fc13a1f2f7e45aecf90d69043380ad167fad0343632937f41
# No package installs: `ubi-minimal` already carries the system trust store. The health documents
# this reconciler reads live on an HTTPS CDN, and the TLS backend loads the platform verifier when
# the client is CONSTRUCTED — so without it the process fails at startup rather than on a request,
# with an error naming neither certificates nor this image. Asserted, not assumed.
RUN test -e /etc/pki/tls/certs/ca-bundle.crt && \
    useradd --uid 65532 --create-home updated
COPY --from=build /tmp/updated-healthproxy /usr/local/bin/updated-healthproxy
USER 65532
ENTRYPOINT ["/usr/local/bin/updated-healthproxy"]
