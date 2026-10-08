# syntax=docker/dockerfile:1.7
# vmcp service image for the Firecracker runtime. The Firecracker binary is
# embedded in the vmcp binary from runtimes/firecracker/release. The jailer
# from the same release is extracted at build time, because it needs file
# capabilities; vmcp verifies its size and SHA-256 against the lock before
# it uses it. The guest kernel is fetched at build time and checked by
# SHA-256.
#
# vmcp runs as UID and GID 65532. Its capabilities come from file
# capabilities on the vmcp binary and on the jailer. Run the image with the
# settings in AGENTS.md (Deployment). Do not set no-new-privileges: it stops
# the kernel from granting file capabilities. Do not publish its port on a
# host interface. Run vmcp host commands with --user 0:0.

FROM golang:1.26.2-bookworm@sha256:47ce5636e9936b2c5cbf708925578ef386b4f8872aec74a67bd13a627d242b19 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY api ./api
COPY client ./client
COPY cmd ./cmd
COPY runtimes ./runtimes
COPY internal ./internal
ARG VMCP_VERSION=dev
ARG VMCP_COMMIT=unknown
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -buildid= -X main.version=${VMCP_VERSION} -X main.commit=${VMCP_COMMIT}" -o /out/vmcp ./cmd/vmcp \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags='-s -w -buildid=' -o /out/vmcp-agent ./runtimes/firecracker/cmd/vmcp-agent \
 && gzip -dc runtimes/firecracker/release/linux/amd64/jailer.gz > /out/jailer

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
LABEL org.opencontainers.image.title="vmcp" \
      org.opencontainers.image.source="https://github.com/jaredfolkins/vmcp" \
      org.opencontainers.image.licenses="NOASSERTION"
# apparmor and kmod serve vmcp host install (apparmor_parser, modprobe).
# libcap2-bin sets the file capabilities below.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      iproute2 nftables e2fsprogs ca-certificates tini apparmor kmod libcap2-bin \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 65532 vmcp \
 && useradd --system --uid 65532 --gid 65532 --no-create-home \
      --home-dir /var/lib/vmcp --shell /usr/sbin/nologin vmcp \
 && find / -xdev -type f -perm /6000 -exec chmod ug-s {} + \
 && install -d -o 65532 -g 65532 -m 0700 /var/lib/vmcp \
 && install -d -m 0755 /usr/share/vmcp
ADD --checksum=sha256:aa31ad182c31a0bb45fa72362973b1e584378ae55faef06b94b7c4b6a0862afc --chmod=0444 \
    https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260723-ae5bf5b68fc4-0/x86_64/vmlinux-5.10.260 \
    /usr/share/vmcp/vmlinux
COPY --from=build --chown=0:0 --chmod=0555 /out/vmcp-agent /usr/libexec/vmcp/vmcp-agent
COPY --from=build --chown=0:0 --chmod=0555 /out/jailer /usr/libexec/vmcp/jailer
COPY --from=build --chown=0:0 --chmod=0555 /out/vmcp /usr/local/bin/vmcp
# File capabilities do not survive COPY reliably, so set them here. vmcp
# raises a subset into the ambient set of each tool that needs one. The
# jailer gets its own set from its file, so Firecracker starts with none.
RUN setcap cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_net_admin,cap_net_bind_service=eip \
      /usr/local/bin/vmcp \
 && setcap cap_chown,cap_dac_override,cap_mknod,cap_setgid,cap_setuid,cap_sys_admin=ep \
      /usr/libexec/vmcp/jailer
USER 65532:65532
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=6 \
    CMD ["/usr/local/bin/vmcp", "healthcheck"]
# With --new-pid-ns the jailer exits after it starts Firecracker, so
# Firecracker is reparented to PID 1. tini is PID 1: it reaps those
# processes and forwards signals to vmcp.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/vmcp"]
CMD ["serve", "--listen", ":8080", "--credential-file", "/run/secrets/vmcp-credential"]
