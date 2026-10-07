# vmcp

vmcp is a small control plane for virtual machines. It installs a VM runtime
on a host and serves an HTTP API that runs and manages machines:

- **Ephemeral machines** run one process in a fresh guest. vmcp destroys the
  guest when the process stops and keeps its output drives until you delete
  the machine.
- **Persistent machines** keep their disk and drives. You can stop, start,
  restart, attach to, expose ports of, snapshot, and restore them.

> **Status: early.** The API in [`api/`](api/api.go) is a draft. Today
> `vmcp serve` implements only the health and status routes. See
> [BACKLOG.md](BACKLOG.md) for the work in progress.

## Runtimes

| Runtime | Hosts | Status |
| --- | --- | --- |
| [Firecracker](runtimes/firecracker/) | Linux amd64: Debian 12, Ubuntu 24.04 | Firecracker and jailer `1.16.0` baked in; health and status |
| Apple [`container`](https://github.com/apple/container) | macOS 26, Apple silicon | Planned |

One vmcp binary serves one runtime: the runtime of the OS it is built for.

## Design

- **One caller, one credential.** Every route except `GET /healthz` and
  `GET /ready` needs a bearer credential from an owner-private file. Run vmcp on a private
  network that only its caller can reach. Do not publish its port on a host
  interface.
- **Baked release.** The Firecracker and jailer binaries are embedded in the
  vmcp binary with a lock of their sizes and SHA-256 sums. vmcp uses a binary
  only after it matches the lock. Nothing is downloaded at install or run
  time.
- **Isolated guests.** Each Firecracker guest runs under the jailer with its
  own chroot, cgroup, and PID namespace. A guest reaches only brokered DNS,
  policy-controlled public egress, and the exact upstream services in its
  spec. Host and private networks and cloud metadata are always denied.
- **Tokens stay on the host.** An upstream token in a request is used only
  by a host broker. It never enters a guest and is never returned or logged.
- **Install tears down first.** Every install, upgrade, and rollback removes
  everything that vmcp owns except the state needed to upgrade, then installs
  again and verifies with real machines.

## Quick start

You need Linux amd64 with `/dev/kvm`, `/dev/net/tun`, cgroup v2, and Docker.

```bash
docker build -t vmcp:dev .

umask 077
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > vmcp-credential

docker run -d --name vmcp \
  --user "$(id -u):$(id -g)" \
  --group-add "$(getent group kvm | cut -d: -f3)" \
  --device /dev/kvm --device /dev/net/tun \
  -v "$PWD/vmcp-credential:/run/secrets/vmcp-credential:ro" \
  -p 127.0.0.1:18080:8080 \
  vmcp:dev

curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/healthz
curl -s -H "Authorization: Bearer $(cat vmcp-credential)" \
  http://127.0.0.1:18080/v1/status
```

The health route answers `204`. The status route reports the runtime, the
baked release, the host checks, and the host capacity.

This local run uses your own user so that the container can read the
credential, and it binds the port to loopback only. A production deployment
runs vmcp as UID `65532` with a `0400` credential that this user owns, the
runtime's seccomp and AppArmor profiles, and no published port. See
[AGENTS.md](AGENTS.md#deployment).

## Host preparation

Each runtime has one installer folder per supported OS. For Firecracker:

```bash
runtimes/firecracker/installers/linux/ubuntu/24.04/amd64/prepare-host.sh --check
sudo runtimes/firecracker/installers/linux/ubuntu/24.04/amd64/prepare-host.sh --apply
```

`--check` makes no changes. `--apply` installs missing packages, loads the
KVM and TUN modules, and starts Docker. Use the `debian/12` folder on
Debian 12.

## API

The routes and types are in [`api/api.go`](api/api.go).

| Area | Routes |
| --- | --- |
| Service | `GET /healthz`, `GET /ready`, `GET /v1/status`, `POST /v1/selftest` |
| Images | `POST`, `GET /v1/images`, `GET`, `DELETE /v1/images/{id}` |
| Machines | `POST`, `GET /v1/machines`, `GET`, `DELETE /v1/machines/{id}`, `POST .../start`, `.../stop`, `.../restart` |
| Drives and events | `PUT`, `GET /v1/machines/{id}/drives/{name}`, `GET /v1/machines/{id}/events` |
| Exec and console | `POST /v1/machines/{id}/exec`, WebSocket `.../exec/{session}` and `.../console` |
| Snapshots | `POST`, `GET /v1/machines/{id}/snapshots`, `POST .../restore`, `DELETE /v1/snapshots/{id}` |

## Development

Go is pinned to `1.26.2`.

```bash
go test ./...
go vet ./...
golangci-lint run ./...   # v2.12.2
shellcheck runtimes/*/installers/*/*/*/*/*.sh
docker build -t vmcp:dev .
```

Changes to a runtime, its networking, install, or cleanup also need that
runtime's live gate on a real KVM host. [AGENTS.md](AGENTS.md) has the rules
for contributors and coding agents.

## Layout

```text
api/                     HTTP contract
cmd/vmcp/                vmcp serve and vmcp healthcheck
internal/server/         HTTP server and authentication
runtimes/firecracker/    Firecracker runtime, baked release, installers
Dockerfile               Linux service image
AGENTS.md                rules for contributors and agents
BACKLOG.md               work list
```

## License

vmcp has no license yet. The Firecracker and jailer binaries in
[`runtimes/firecracker/release/`](runtimes/firecracker/release/) are
Apache-2.0; their `LICENSE`, `NOTICE`, and `THIRD-PARTY` files are next to
them.
