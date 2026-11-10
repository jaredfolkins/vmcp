# vmcp

vmcp is a small control plane for virtual machines. It installs a VM runtime
on a host and serves an HTTP API that runs and manages machines:

- **Ephemeral machines** run one process in a fresh guest. vmcp destroys the
  guest when the process stops and keeps its output drives until you delete
  the machine.
- **Persistent machines** keep their disk and drives. You can stop, start,
  restart, attach to, expose ports of, snapshot, and restore them.

> **Status: early.** The API in [`api/`](api/api.go) is a draft. Ephemeral
> machines work today: images, machines, start, stop, delete, drives,
> events, and the runtime self-test. Restart, exec, console, ports, and
> snapshots are planned. See [BACKLOG.md](BACKLOG.md).

## Runtimes

| Runtime | Hosts | Status |
| --- | --- | --- |
| [Firecracker](runtimes/firecracker/) | Linux amd64: Debian 12, Ubuntu 24.04 | Firecracker and jailer `1.16.0` baked in; ephemeral machines |
| Apple [`container`](https://github.com/apple/container) | macOS 26, Apple silicon | Planned |

One vmcp binary serves one runtime: the runtime of the OS it is built for.

## Design

- **One caller, one credential.** Every route except `GET /health` and
  `GET /ready` needs a bearer credential from an owner-private file. Run vmcp
  on a private network that only its caller can reach. Do not publish its
  port on a host interface.
- **Baked release.** The Firecracker and jailer binaries are embedded in the
  vmcp binary with a lock of their sizes and SHA-256 sums. vmcp uses a binary
  only after it matches the lock. Nothing is downloaded at install or run
  time.
- **Isolated guests.** Each Firecracker guest runs under the jailer with its
  own chroot, cgroup, and PID namespace. A guest reaches only brokered DNS,
  policy-controlled public egress, and the exact upstream services in its
  spec. Host and private networks and cloud metadata are always denied.
- **Non-root and confined.** vmcp runs as UID `65532` with file
  capabilities, its own AppArmor profile, and a seccomp profile. Each tool
  and the jailer get only the capabilities that they need. Firecracker
  gets none.
- **Tokens stay on the host.** An upstream token in a request is used only
  by a host broker. It never enters a guest and is never returned or logged.
- **Debuggable log.** One JSON line per API call and per machine step.
  vmcp continues the caller's W3C `traceparent`, so one trace ID finds a
  request and every machine step that it started. `--log-level` selects
  `debug`, `info`, `warn`, or `error`.
- **Self-installing.** `docker compose up` prepares the host on the first
  start: a one-shot service writes what is missing and changes nothing
  after that. `vmcp host install` is the reset: it removes everything that
  vmcp owns except the state needed to upgrade, then installs again. Every host resource carries the
  install identity, so teardown removes only what vmcp made, from any vmcp
  version.

## Quick start

You need Linux amd64 with `/dev/kvm`, cgroup v2, AppArmor, and Docker.

```bash
docker compose up -d
```

[`compose.yaml`](compose.yaml) has two services. `vmcp-host` runs once
before each start of `vmcp`. It runs `vmcp host ensure`, which installs the
host resources of the install on the first start and changes nothing on a
later start. It also creates the caller credential in the volume
`vmcp-credential` when none exists. Then `vmcp` starts. Set
`VMCP_INSTALL_ID` to name the install; the default is `main`.

```bash
cred=$(docker compose run --rm --no-deps -u 0 --entrypoint cat vmcp /run/secrets/vmcp-credential)
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/ready
curl -s -H "Authorization: Bearer $cred" http://127.0.0.1:18080/v1/status
curl -s -X POST -H "Authorization: Bearer $cred" http://127.0.0.1:18080/v1/selftest
```

The ready route answers `204` when the runtime is ready. The status route
reports the runtime, the baked release, the host checks, and the host
capacity. The self-test boots a guest and proves from inside it that the
host, private networks, and cloud metadata are unreachable.

Two rules for a Compose file of your own:

- Compose reads the seccomp profile when it creates the `vmcp` container,
  before `vmcp-host` runs. So keep
  [`runtimes/firecracker/deploy/seccomp.json`](runtimes/firecracker/deploy/seccomp.json)
  next to the Compose file and name it with a relative path. Docker checks
  the AppArmor profile only when the container starts, after `vmcp-host`.
- vmcp runs as UID `65532`. Its capabilities come from file capabilities
  on the vmcp binary and on the jailer, so do not set `no-new-privileges`:
  it stops the kernel from granting them, and vmcp then refuses to start.
  Docker's default seccomp profile blocks the jailer `pivot_root`.

The quick start binds the port to loopback only. A deployment publishes no
port. See [AGENTS.md](AGENTS.md#deployment).

To remove it:

```bash
docker compose down -v
docker compose run --rm --no-deps vmcp-host host teardown --install-id main
```

## Host install

`vmcp host check|ensure|install|teardown|status --install-id <id>` manage
the host resources of one install. They run as root from the vmcp image in
a one-shot container with the settings of the `vmcp-host` service, and
each prints one JSON result.

| Command | What it does |
| --- | --- |
| `check` | Checks root, the host `/etc` mount, cgroup v2, AppArmor, the host processes, and CPU virtualization. No change. |
| `ensure` | Runs `check`, then writes only the resources that are missing or differ from what this version writes. It removes nothing, and it does not need the service to stop. A second run changes nothing. With `--credential-file` it also creates the caller credential when the file does not exist. |
| `install` | Runs `check` and `teardown`, then writes the seccomp profile, the AppArmor profile `vmcp-<id>` (loaded in enforce mode), the parent cgroup `vmcp-<id>` delegated to UID `65532`, `/etc/tmpfiles.d/vmcp-<id>.conf`, which creates that cgroup again at each host boot, and the KVM and TUN module file. It verifies them and writes `/etc/vmcp/<id>/receipt.json` last. |
| `teardown` | Removes every host resource with the tag of the install, also from older vmcp versions. Refuses while the vmcp service of the install runs. |
| `status` | Prints the tagged inventory, whether the service runs, and the receipt. |

Every host resource carries the install identity: the first line
`# vmcp-owner: <id>` of each host text file, a marker file in
`/etc/vmcp/<id>/`, the `trusted.vmcp.owner` attribute of the parent cgroup,
the profile name `vmcp-<id>`, the alias `vmcp:<id>:...` of host links, and
the comment `vmcp:<id>` of the vmcp nftables table. Teardown finds
resources by these tags and removes only them. It reports an untagged
look-alike or a resource of another install and does not touch it.
`vmcp serve` holds a lock on its parent cgroup while it runs, and every
vmcp version watches that cgroup. `install` and `teardown` refuse while a
process holds the lock or the watch, so stop the vmcp service first. They
need `--pid=host` and `SYS_PTRACE` to see the host processes, and refuse
without them.

A host reboot empties the cgroup file system. The install brings itself
back before Docker starts the service: AppArmor loads the profile,
`systemd-modules-load` loads the modules, and `systemd-tmpfiles-setup`
creates the parent cgroup with its tag, its controllers, and its
delegation to the service user. A live gate proved the cgroup part with
`systemd-tmpfiles --create` after the cgroup was removed. A real reboot
is not verified yet. See [AGENTS.md](AGENTS.md#host-boot).

## Compose

[`compose.yaml`](compose.yaml) is the reference. In a deployment, drop its
`ports` and `build` keys, name the image by digest, and put `vmcp` on a
private network with its one caller. Mount the volume `vmcp-credential`
read-only into the caller too, or pass your own credential file (owner
`65532`, mode `0400`) at `/run/secrets/vmcp-credential`.

Do not add `no-new-privileges`, `init`, or `ports` to `vmcp`.

After a host boot Docker starts `vmcp` without `vmcp-host`. The host files
of the install bring the resources back first (see Host install). When they
do not, `vmcp` stops with a clear error, and `docker compose up -d` repairs
the host.

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
| Service | `GET /health`, `GET /ready`, `GET /v1/status`, `POST /v1/selftest` |
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
client/                  Go client
cmd/vmcp/                vmcp serve, healthcheck, and host
internal/machine/        runtime-neutral machine manager
internal/server/         HTTP server and authentication
internal/trace/          W3C trace context, spans, and the log handler
e2e/                     end-to-end tests against a running vmcp
runtimes/firecracker/    Firecracker runtime, baked release, installers,
                         seccomp profile, AppArmor profile template
Dockerfile               Linux service image
AGENTS.md                rules for contributors and agents
BACKLOG.md               work list
```

## License

vmcp has no license yet. The Firecracker and jailer binaries in
[`runtimes/firecracker/release/`](runtimes/firecracker/release/) are
Apache-2.0; their `LICENSE`, `NOTICE`, and `THIRD-PARTY` files are next to
them.
