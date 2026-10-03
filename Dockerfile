# Pinned by digest so image rebuilds are reproducible. Update this digest
# (and re-run the build) when bumping the toolchain; it tracks
# docker.io/library/rust:alpine.
FROM docker.io/library/rust:alpine@sha256:a96ea6d18d4062e38f16cfbadd8b4541d622f2527dd0a5eca1fb36d301da4e88 AS builder
ARG TARGETARCH
RUN apk add --no-cache musl-dev

WORKDIR /work
COPY Cargo.toml Cargo.lock /work/
COPY src/ /work/src/
# The deploy stage is FROM scratch, so the binary must be fully static:
# build explicitly for the musl target of the architecture being built
# (Docker's TARGETARCH is mapped to Rust's target triple; on non-buildkit
# builders TARGETARCH is unset and we fall back to uname -m).
# --locked: the build must not move Cargo.lock.
RUN --mount=type=cache,dst=/usr/local/cargo/registry,id=cargo-registry \
    set -eu; \
    arch="${TARGETARCH:-$(uname -m)}"; \
    case "${arch}" in \
      amd64|x86_64) rust_target=x86_64-unknown-linux-musl ;; \
      arm64|aarch64) rust_target=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported architecture: ${arch}" >&2; exit 1 ;; \
    esac; \
    rustup target add "${rust_target}"; \
    TERM=dumb cargo build --release --locked --target "${rust_target}"; \
    cp "target/${rust_target}/release/wlsctx" /wlsctx

FROM scratch AS deploy
COPY --from=builder /wlsctx /wlsctx
ENTRYPOINT [ "/wlsctx" ]
CMD []
