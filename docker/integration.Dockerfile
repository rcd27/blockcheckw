FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# ── System deps for nfqws2 + Rust ────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    nftables \
    conntrack \
    libnetfilter-queue-dev \
    libnfnetlink-dev \
    libmnl-dev \
    libcap-dev \
    libluajit-5.1-dev \
    zlib1g-dev \
    curl \
    ca-certificates \
    procps \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# ── Rust toolchain ────────────────────────────────────────────────────────────
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

# ── Build nfqws2 from submodule source ────────────────────────────────────────
COPY reference/zapret2/nfq2/ /build/nfq2/
WORKDIR /build/nfq2
RUN make nfqws2

# Install nfqws2 + lua scripts into /opt/zapret2
RUN mkdir -p /opt/zapret2/binaries/linux-x86_64 /opt/zapret2/lua
RUN cp nfqws2 /opt/zapret2/binaries/linux-x86_64/nfqws2
COPY reference/zapret2/lua/ /opt/zapret2/lua/

# ── Cargo fetch (cached layer) ────────────────────────────────────────────────
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs && cargo fetch && rm -rf src

# ── Copy source + tests + strategies ──────────────────────────────────────────
COPY src/ src/
COPY tests/ tests/
COPY strategies/ strategies/

# ── Build test binaries (no-run = compile only) ──────────────────────────────
RUN cargo test --test e2e_infra --test parallel_benchmark --no-run 2>&1

ENTRYPOINT ["cargo", "test"]
