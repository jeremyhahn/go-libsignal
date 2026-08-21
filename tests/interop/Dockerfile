# Multi-stage Dockerfile for SPQR live interop testing.
#
# Stage 1: build the Rust interop CLI binary.
# Stage 2: run the Go interop test suite with the Rust binary available.

# ---------------------------------------------------------------------------
# Stage 1: Rust build
# ---------------------------------------------------------------------------
FROM rust:1.85-bookworm AS rust-builder

# The spqr crate's build.rs invokes protoc to compile its .proto schema.
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy only the Rust crate to cache cargo dependencies separately from source.
COPY tests/interop/rust/Cargo.toml ./Cargo.toml

# Create a stub main so cargo can fetch and compile dependencies before the
# real source is copied. This layer is cached as long as Cargo.toml is unchanged.
RUN mkdir -p src && \
    echo 'fn main() {}' > src/main.rs && \
    cargo build --release 2>&1 || true

# Copy the real source and build the final binary.
COPY tests/interop/rust/src ./src
RUN touch src/main.rs && cargo build --release

# ---------------------------------------------------------------------------
# Stage 2: Go test runner
# ---------------------------------------------------------------------------
FROM golang:1.26.7-bookworm AS test-runner

# Install the Rust interop binary from stage 1.
COPY --from=rust-builder /build/target/release/libsignal-interop /usr/local/bin/libsignal-interop

# Copy the entire repository.
WORKDIR /repo
COPY . .

# Set the interop binary location for the Go tests.
ENV LIBSIGNAL_INTEROP_BIN=/usr/local/bin/libsignal-interop

# Run the live interop tests. GOWORK=off is required because the repo root
# may contain a go.work file that interferes with module resolution.
CMD ["sh", "-c", "GOWORK=off go test -tags=interop_live -race -v ./tests/interop/..."]
