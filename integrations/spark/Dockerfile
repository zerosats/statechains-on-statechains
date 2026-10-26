# The upstream native runner provisions checksum-verified Linux x86-64 tools.
FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS go
FROM rust:1.95.0-slim-bookworm@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082

COPY --from=go /usr/local/go /usr/local/go
RUN /usr/local/go/bin/go version
# The runner creates its own database under .regtest; no system cluster is needed.
RUN mkdir -p /etc/postgresql-common \
    && printf 'create_main_cluster = false\n' > /etc/postgresql-common/createcluster.conf \
    && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl git unzip python3 pkg-config libssl-dev libzmq3-dev \
    libprotobuf-dev protobuf-compiler postgresql libpq-dev libclang-dev \
    && rm -rf /var/lib/apt/lists/*
ENV PATH="/usr/local/go/bin:${PATH}" \
    CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
    GOMAXPROCS=2 GOTOOLCHAIN=local

# PostgreSQL refuses root. Keep source/build caches owned by the fixture user.
ARG RUNNER_UID=1000
RUN useradd --create-home --uid ${RUNNER_UID} regtest \
    && chown -R regtest:regtest /usr/local/cargo
USER regtest
WORKDIR /src/open-ssp
CMD ["sleep", "infinity"]
