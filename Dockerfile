# syntax=docker/dockerfile:1.7
# vmcp service image for the Firecracker runtime. The Firecracker and jailer
# binaries are embedded in the vmcp binary from runtimes/firecracker/release.
# The guest kernel is fetched at build time and checked by SHA-256.
#
# Run it with the devices, capabilities, and profiles from AGENTS.md
# (Deployment). Do not publish its port on a host interface.

FROM golang:1.26.2-bookworm@sha256:47ce5636e9936b2c5cbf708925578ef386b4f8872aec74a67bd13a627d242b19 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY api ./api
COPY client ./client
COPY cmd ./cmd
COPY runtimes ./runtimes
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags='-s -w -buildid=' -o /out/vmcp ./cmd/vmcp \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags='-s -w -buildid=' -o /out/vmcp-agent ./runtimes/firecracker/cmd/vmcp-agent

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
LABEL org.opencontainers.image.title="vmcp" \
      org.opencontainers.image.source="https://github.com/jaredfolkins/vmcp" \
      org.opencontainers.image.licenses="NOASSERTION"
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      iproute2 nftables e2fsprogs ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:aa31ad182c31a0bb45fa72362973b1e584378ae55faef06b94b7c4b6a0862afc --chmod=0444 \
    https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260723-ae5bf5b68fc4-0/x86_64/vmlinux-5.10.260 \
    /usr/share/vmcp/vmlinux
COPY --from=build --chown=0:0 --chmod=0555 /out/vmcp /usr/local/bin/vmcp
COPY --from=build --chown=0:0 --chmod=0555 /out/vmcp-agent /usr/libexec/vmcp/vmcp-agent
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=6 \
    CMD ["/usr/local/bin/vmcp", "healthcheck"]
# With --new-pid-ns the jailer exits after it starts Firecracker, so
# Firecracker is reparented to PID 1. tini is PID 1: it reaps those
# processes and forwards signals to vmcp.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/vmcp"]
CMD ["serve", "--listen", ":8080", "--credential-file", "/run/secrets/vmcp-credential"]
