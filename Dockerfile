# vmcp service image. The Firecracker and jailer binaries are embedded in
# the vmcp binary from runtimes/firecracker/release.
#
# Run it with the devices, capabilities, and profiles from AGENTS.md
# (Deployment). Do not publish its port on a host interface.

FROM golang:1.26.2-bookworm@sha256:47ce5636e9936b2c5cbf708925578ef386b4f8872aec74a67bd13a627d242b19 AS build
WORKDIR /src
COPY go.mod ./
COPY api ./api
COPY cmd ./cmd
COPY runtimes ./runtimes
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags='-s -w -buildid=' -o /out/vmcp ./cmd/vmcp

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
LABEL org.opencontainers.image.title="vmcp" \
      org.opencontainers.image.source="https://github.com/jaredfolkins/vmcp" \
      org.opencontainers.image.licenses="NOASSERTION"
COPY --from=build --chown=0:0 --chmod=0555 /out/vmcp /usr/local/bin/vmcp
USER 65532:65532
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=6 \
    CMD ["/usr/local/bin/vmcp", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/vmcp"]
CMD ["serve", "--listen", ":8080", "--credential-file", "/run/secrets/vmcp-credential"]
