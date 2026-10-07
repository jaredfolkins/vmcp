# vmcp Agent Guide

## Purpose
- `vmcp` (module `github.com/jaredfolkins/vmcp`) is a VM control plane
  service. It installs, configures, upgrades, and removes one VM technology
  on its host. Its HTTP API runs and manages machines, both ephemeral and
  persistent.
- `runtimes/firecracker/` is the only runtime. Every runtime follows the
  same contract (see [Runtimes](#runtimes)).
- vmcp does not know its caller's domain. LEMC (`../letemcook-private`) is
  the first caller. The LEMC Runner goes away. The LEMC Web server calls the
  vmcp API directly. LEMCSSH and other LEMC clients reach machines only
  through Web.
- The work is not complete. Read [Current State](#current-state) and
  [BACKLOG.md](BACKLOG.md) before a change.

## User Communication
- All reports and replies must use ASD-STE100 Simplified Technical English.
- State facts, decisions, failures, and next actions with short direct
  sentences.
- Mark a claim that no executed check proves as `NOT VERIFIED`.

## Current State
- `api/` is the draft HTTP contract. Routes and fields can change until LEMC
  uses them in production.
- `cmd/vmcp serve` implements only `GET /healthz` and `GET /v1/status`.
  Every other route answers `not_found` after authentication.
  `vmcp healthcheck` probes the health route.
- `Dockerfile` builds the service image from the LEMC-pinned Go and Debian
  images. A local run on this host with `/dev/kvm` and `/dev/net/tun`
  returned health 204, status 401 without the credential, and a ready status
  with the credential. SIGTERM stopped it with exit code 0.
- `runtimes/firecracker/release/` bakes in Firecracker `1.16.0` and jailer `1.16.0`,
  linux/amd64, from the official upstream archive. The archive matches the
  GitHub asset digest and the published `.sha256.txt`. Both binaries match
  the archive `SHA256SUMS`. `go test ./firecracker` proves that the embedded
  bytes match the lock.
- LEMC still ships Firecracker `1.12.0` and runs jobs through its Runner. The
  LEMC jailer lab document records a passed jailer proof with official
  `1.16.0` on this host. A guest boot with the LEMC guest kernel and rootfs on
  `1.16.0` is `NOT VERIFIED`.
- `runtimes/firecracker/installers/` has Debian 12 and Ubuntu 24.04 amd64 host
  preparation scripts. The OS identity gate was checked in containers. The
  package, device, and Docker checks are `NOT VERIFIED` on a real Debian 12
  host.
- The remote is `git@github.com:jaredfolkins/vmcp.git`. The repository is
  public. Do not push private LEMC data, credentials, host names, or
  operator paths.

## Scope And Budget
- Do the selected backlog item and its acceptance checks. Then stop.
- Do not start a later task, an adjacent cleanup, or a new framework
  without explicit user direction.
- Repair the first failing owner. Do not add a fallback, retry, alias, or
  second path to avoid a failure.
- Reuse evidence that is already in context. Do not repeat broad searches or
  checks without a changed input.
- Report an unrelated defect briefly. Leave it unchanged. Lint repairs are
  always allowed.

## Ownership Boundary

### vmcp owns
- The HTTP API, its authentication, and its audit log.
- Machines: provisioning, boot, process, events, drives, files, stop,
  restart, exec, console, ports, snapshots, destroy, and proofs.
- Isolation: jail, cgroups, guest network, brokers, and cleanup.
- Recovery after a vmcp restart.
- Prepared images: OCI image conversion and the local image cache.
- The baked release and the install, upgrade, rollback, and teardown of
  everything that it owns on the host.
- Its image, its OS installer folders, and its live gates.

### LEMC owns
- Users, accounts, authorization, scheduling, the job hold, and
  persistence.
- The decision to create, start, stop, attach to, expose, snapshot, or
  delete each machine.
- The mapping from a job, a Provider call, or a Builder run to a
  `MachineSpec`.
- Output classification into LEMC verbs, storage publication, and object
  keys.
- All user access. LEMCSSH, the browser, and `lemcli` reach machines only
  through Web. Web relays consoles, exec sessions, events, and ports.
- The decision to install or upgrade vmcp.

### Neutrality rules
- This module never imports LEMC. LEMC imports `api` and, after backlog
  item V2, `client`.
- Do not add caller concepts to vmcp: no job, lease, task, account, recipe,
  Cookbook, Provider, verb, or object key. Use machine, image, drive, file,
  upstream, port, snapshot, label, and event.
- Labels are opaque caller data. vmcp stores and filters them. It never
  interprets them.
- Tokens in a request are opaque. Only host brokers use them. A token never
  enters a guest and is never returned or logged.
- No database, queue, or object-store client in vmcp.

## The API
- HTTP/1.1 with JSON bodies. Drive content is a tar body. Events are
  newline-delimited JSON. Exec and console attach use WebSocket.
- Every route except `GET /healthz` needs `Authorization: Bearer
  <credential>`. The credential is one owner-private file. One caller (LEMC
  Web) holds it. vmcp compares credential hashes in constant time.
- vmcp listens only on the private service network that it shares with Web.
  Never publish its port on a host interface.
- Errors use `api.ErrorResponse` with a fixed `api.ErrorCode` and a safe
  message.
- A create with an existing `name` and the same spec returns the existing
  machine. A different spec with the same name is a conflict.
- Every machine event has a sequence number. A caller resumes a stream with
  `after`.
- `api/api.go` lists the draft routes. The server registers a route only
  when a backlog item implements it with its tests.

### Change rules
- A change to an exported identifier, route, or JSON field in `api` is an
  API change. Update vmcp and LEMC in one coordinated change.
- Do not keep an old and a new API shape at the same time without a named
  compatibility range and a removal condition.
- A new runtime must not change the API.

## Machines

### Ephemeral
- One process in one fresh guest. A guest is never reused.
- Flow: create (provisioned and isolated, not booted), upload input drives,
  start, follow events to the exit event, download writable drives, and
  delete.
- vmcp destroys the guest when the process exits, times out, exceeds its
  output limit, or is stopped. The machine then has state `exited` and a
  proof. Its writable drives stay readable until the caller deletes the
  machine.
- `TimeoutSeconds` is required.

### Persistent
- A named machine with its own root disk and drives. It keeps them across
  stop, start, restart, vmcp restart, and vmcp upgrade.
- `Restart` controls what happens when its process stops and when vmcp
  starts: `never`, `on-failure`, or `always`. A boot after a vmcp restart is
  a fresh boot from disk; memory state is lost unless a snapshot is
  restored.
- Exec and console: Web creates an exec session or attaches to the serial
  console. Web authorizes each user and relays the WebSocket. Log the
  session start and end, not its content.
- Ports: vmcp exposes a guest port only on the service network. The machine
  response lists each endpoint. Web authorizes and proxies user traffic.
- Snapshots: vmcp pauses the guest, saves memory, device state, and disk,
  and resumes it. Restore needs a stopped machine and the same runtime
  release that made the snapshot. Restore replaces the machine state in
  place. Do not clone a snapshot into a second machine.

### Recovery
- When vmcp starts, it destroys every ephemeral guest that an earlier
  process left. Each one gets state `failed`, exit reason `failed`, and a
  proof.
- Persistent machines follow their restart policy.
- After a Web restart, Web lists machines by label and reconciles them with
  its own records.

## How LEMC Uses vmcp
| LEMC Runner today | With vmcp |
| --- | --- |
| Runner registration, session, actual state, drain | Removed. Web reads `GET /v1/status`. |
| Lease poll, heartbeat, execute token | Removed. Web owns the job and calls vmcp directly. |
| Provider verify and jailed self-test | `GET /v1/status`, `POST /v1/selftest` |
| Rootfs prewarm, artifact upload, image-ready retention | `POST /v1/images` and the vmcp image cache |
| `provision-jail` before guest boot (ADR 0043 in LEMC) | Create; Web records the step; then start |
| Registry proxy, pull-only or builder-push | `network.upstreams` with `allow_write` |
| Guest events through the control proxy | `GET /v1/machines/{id}/events`; Web classifies into LEMC verbs |
| Workspace hydration and storage publication | Upload and download drives; Web publishes to object storage |
| Provider activation guest with a Secret | One ephemeral machine with a secret file; result from a drive |
| Secret redaction of guest output | `redactions` |
| Cancel, timeout, lost heartbeat | Stop or delete; `timeout_seconds`; vmcp recovery |
| `JobProof` | `api.Proof`; Web adds its object keys |

## Runtimes
- A runtime is one VM technology. Each runtime lives in
  `runtimes/<runtime>/` with its code, baked release, installers, and
  deploy profiles. `runtimes/firecracker/` is the only one.
- The second runtime will drive Apple `container` on macOS. It is a
  deferred item in BACKLOG.md.
- Do not add a shared runtime interface, registry, or plugin loader before
  the second runtime needs it.
- Each runtime builds only for its own host OS. Use Go build constraints:
  Firecracker is `linux`. `cmd/vmcp` selects the runtime of the OS it is
  built for. One vmcp binary serves one runtime.
- A runtime is supported only after it implements every route in `api`
  that its backlog item names, provides OS installer folders, provides an
  owned-resource inventory for teardown and status, and passes its live gate
  on each listed OS.
- A runtime may reject an `api` feature that its technology cannot provide.
  It must answer with a fixed error code, not a partial behavior.
- All runtimes and the service stay in one Go module. Split a runtime into
  its own module only when its dependencies conflict with the rest.

### Firecracker rules
- Always use the jailer. Run each guest with a non-root UID and GID, a
  chroot, cgroup v2 limits, rlimits, and a new PID namespace.
- vmcp sets `no_new_privs` on itself at startup, so the jailer and every
  Firecracker process inherit it.
- Host and guest talk only over vsock. The guest agent sends events and the
  tar of each writable drive to the host. The host never mounts or parses a
  guest ext4 image.
- Keep the jail base path short, such as `/var/lib/vmcp/jail`. A Unix socket
  path in a jail must stay under the 108-byte limit.
- Guest network: one tap device per machine in the vmcp network namespace,
  one dedicated nftables table, and brokers written in Go inside vmcp. There
  is no forwarding and no NAT from a tap.
- The guest kernel and other large guest inputs are downloaded at image
  build time and pinned by SHA-256. They are never downloaded at install or
  run time.
- vmcp runs as UID and GID `65532` with file or container capabilities, a
  seccomp profile, and an AppArmor profile. Only development may run as root
  and unconfined.
- Firecracker and the jailer are baked in. `runtimes/firecracker/release/` holds the
  gzip binaries and `release-v1.json`, the lock with the upstream archive URL
  and SHA-256 and each binary's size, SHA-256, and mode. vmcp writes a binary
  only after its size and SHA-256 match the lock. Never download at install
  or run time.
- Firecracker and the jailer always come from the same upstream release.
- Keep upstream `LICENSE`, `NOTICE`, and `THIRD-PARTY` from the same archive
  next to the binaries. Apache-2.0 requires them for redistribution.
- To change the pair: download the official archive, verify its SHA-256,
  extract only `firecracker-v<version>-x86_64` and `jailer-v<version>-x86_64`,
  check them against the archive `SHA256SUMS`, compress each with
  `gzip -n`, update the lock and the license files, run
  `go test ./firecracker`, and pass the Firecracker live gate. A change of
  release invalidates snapshots from the old release.
- The guest kernel, guest base rootfs, and guest tools are not baked in yet.

## Deployment
- `Dockerfile` builds the Linux image with the `vmcp` binary for the
  Firecracker runtime. The binary embeds the Firecracker release. Pin both
  base images by digest.
- The image has no runtime tools yet. Backlog item V2 adds the pinned packages
  that the moved Firecracker code needs, such as `ip`, `nft`, and `mke2fs`.
- In LEMC, the `vmcp` Compose service replaces the `runner` service. It
  needs:
  - user `65532:65532`, the Runner capability set until a live gate proves a
    smaller set, `/dev/kvm`, and `/dev/net/tun`;
  - the vmcp AppArmor and seccomp profiles;
  - binds for its state root with `rshared` propagation, `/sys/fs/cgroup`,
    and the host network namespace read-only, plus a `/run/netns` tmpfs;
  - the credential file at `/run/secrets/vmcp-credential`, owned by `65532`
    with mode `0400`. Web mounts its own copy;
  - only the private network that it shares with Web, and no `ports`; and
  - the healthcheck `vmcp healthcheck`.
- One vmcp serves one LEMC install on the same host. Multi-host is a later
  decision.

## Host Install, Configuration, And Upgrade

### Supported hosts
| Runtime | OS | Version | Architecture | Folder |
| --- | --- | --- | --- | --- |
| firecracker | Debian | 12 | amd64 | `runtimes/firecracker/installers/linux/debian/12/amd64/` |
| firecracker | Ubuntu | 24.04 | amd64 | `runtimes/firecracker/installers/linux/ubuntu/24.04/amd64/` |

- The folder path is
  `runtimes/<runtime>/installers/<kernel>/<distribution>/<version>/<arch>/`. Use the
  `ID` and `VERSION_ID` values from `/etc/os-release`.
- Firecracker hosts need systemd as PID 1, CPU virtualization flags,
  cgroup v2, rootful Docker, and read-write `/dev/kvm` and `/dev/net/tun`.
- A folder holds only facts and steps that differ by OS. The OS-neutral
  transaction belongs to `vmcp install`.
- A new OS target needs its folder and a passing install live gate on that
  OS. arm64 is not supported.

### Install always tears down first
Every install runs the same transaction. A first install, a reinstall, an
upgrade, a downgrade, a rollback, and a configuration change all use it.
There is no in-place update. Do not skip teardown when the version is
unchanged.

1. **Preflight.** Verify the OS folder matches the host, the host
   prerequisites, the exact input digests, the configuration, and that the
   target release can restore every kept snapshot. Make no change.
2. **Lock.** Take the install lock.
3. **Quiesce.** Require that no ephemeral machine exists. Stop every running
   persistent machine with its stop timeout and record which ones ran.
4. **Record intent.** Write the target release and configuration to the
   journal before the first mutation.
5. **Teardown.** Stop the vmcp service. Remove every vmcp-owned resource
   except the preserved state. Verify removal from a fresh inventory.
6. **Install.** Write the baked release from verified local inputs. Write
   vmcp-owned host configuration. Start the vmcp service with the exact
   image digest and configuration.
7. **Verify.** Pass the self-test. Run one ephemeral machine, verify
   cleanup, run a second one, and check that no machine resource remains.
   Start the persistent machines that ran before step 3 and check them.
8. **Commit.** Write the install receipt only after step 7 passes. Release
   the lock.

### Preserved state
Teardown keeps only this state, in the vmcp state root:

- the operator configuration of the last install;
- the install receipt and journal of the last committed install;
- the release artifacts of the last committed install, for rollback; and
- each persistent machine: its record, root disk, drives, and the snapshots
  that the target release can restore.

All other state is disposable, including prepared images. If the target
release cannot restore a snapshot, preflight stops. The operator can rerun
with an explicit flag that deletes those snapshots.

### Removed on every install
- the vmcp container and its processes;
- jailer and Firecracker processes, jail chroots, and API sockets;
- the parent cgroup and every machine cgroup;
- network namespaces, veth and tap devices, routes, nftables rules, and
  port listeners;
- mounts, broker processes, and broker files;
- the installed release and prepared images;
- scratch files, recovery records, and self-test markers; and
- vmcp-owned host configuration, such as kernel module persistence and the
  loaded AppArmor profile.

Teardown deletes only resources that it can prove vmcp owns. It never
adopts, re-owns, or recursively deletes unowned or conflicting state. It
stops and reports the conflict. OS packages, Docker Engine, the kernel, and
every other LEMC service are not vmcp-owned.

### Failure and rollback
- A failure before teardown leaves the host unchanged.
- A failure after teardown starts automatic rollback: tear down the failed
  attempt, then install the last committed release and configuration with
  the same transaction, and restart the recorded persistent machines.
- If rollback also fails, leave vmcp torn down with only the preserved
  state. Never leave a partly installed vmcp serving. Report both failures,
  the first failed check, and the cleanup result.

### Commands
- `vmcp check`, `vmcp install`, `vmcp teardown`, `vmcp purge` (with an
  explicit confirmation flag), and `vmcp status`. Each writes one JSON
  result. Configuration is one JSON file decoded strictly.
- An operator runs the OS folder entry point with root. Only that path may
  install a missing OS package.
- LEMC `lemc-install` and Angel call `vmcp install`. Angel first places the
  LEMC job hold and waits until no ephemeral machine exists. An automatic
  upgrade does not change OS packages.

## Runtime Security

### Ownership tags
- Tag every host resource that vmcp creates with its install identity:
  - cgroups: the `trusted.vmcp.owner` extended attribute on the parent
    cgroup and on each machine cgroup;
  - files: an owner marker in the state root and in each jail root;
  - network: the `vmcp-` name prefix and an `ifalias` of
    `vmcp:<install>:<machine>` on each tap and veth device;
  - nftables: the one `vmcp` table, with the machine ID in each rule
    comment.
- Inventory, teardown, and status work from these tags. vmcp deletes only
  tagged resources. It reports an untagged or conflicting resource and does
  not touch it.

### Posture contract
After boot, every thread of a jailed Firecracker process must have:
UID and GID `65532`; zero effective, permitted, and ambient capabilities;
`NoNewPrivs: 1`; `Seccomp: 2`; the jail chroot; PID 1 in its own PID
namespace; and its machine cgroup with memory, CPU, and pids limits. Its jail
root holds only the expected files, with no setuid or setgid file and no
device node other than the ones the jailer creates.

### Enforcer
- One enforcer goroutine audits every owned asset all the time. It reacts to
  netlink link, address, and route events, nftables events on the `vmcp`
  table, cgroup events, and jail-root file events. A full sweep every few
  seconds catches anything that an event missed.
- On a violation, it kills the whole machine with `cgroup.kill`, removes
  the unexpected asset or restores the `vmcp` table, records a security
  event, and marks the machine `failed`.
- It acts only inside vmcp's tagged scope. It never signals or deletes a
  process or resource that vmcp does not own.
- It fails closed. If the enforcer stops or falls behind, status is not
  ready and vmcp refuses new machines.
- The enforcer detects and contains. KVM, the jailer, seccomp, cgroups, and
  the network rules prevent.

### Rules
- A guest can reach only its brokers: DNS, policy-controlled public egress,
  and the exact upstreams in its spec. Exposed ports accept traffic only
  from the service network.
- Deny guest access to host loopback, host and private networks, cloud
  metadata, container bridges, and every other host service.
- Never expose a Docker socket, host networking, host PID namespace, host
  root, broad mounts, or catch-all NAT to a guest.
- Never log arbitrary error text, tokens, request bodies, secret file
  bodies, private file contents, exec or console content, or raw guest
  output. Clear secret bytes after use. Apply `redactions` before an event
  leaves vmcp.
- A change to a runtime, networking, brokers, ports, exec, console,
  snapshots, install, teardown, cleanup, or credentials needs the runtime's
  Linux/KVM live gate. Unit tests do not replace it.
- A live gate proves allowed behavior, denied reachability, terminal state,
  and removal of every owned process, jail, cgroup, namespace, tap, rule,
  mount, socket, listener, scratch path, and drive.

## Target Layout
```text
api/                                public HTTP contract
client/                             Go client for callers (V2)
cmd/vmcp/                           serve, healthcheck, and install commands
internal/server/                    HTTP server and authentication
internal/install/                   teardown-first install transaction (V4)
runtimes/firecracker/               Firecracker runtime (linux)
runtimes/firecracker/release/       baked Firecracker and jailer, lock, licenses
runtimes/firecracker/installers/<kernel>/<distribution>/<version>/<arch>/
runtimes/firecracker/cmd/           guest binaries (V2)
runtimes/firecracker/internal/      jail, launch, network, brokers, rootfs, guest (V2)
runtimes/firecracker/deploy/        seccomp and AppArmor profiles (V2)
Dockerfile                          Linux service image
docs/                               design, security, and ADRs
```
- Create a package only when a backlog item moves or writes code into it. Do
  not create empty packages or placeholders.
- Do not create `util`, `common`, `shared`, `helpers`, or `types` packages
  or package-per-file layouts.

## Source Map
Paths on the left are in `../letemcook-private`.

### Moves to vmcp
| Source | Target |
| --- | --- |
| `src/microvmrunner` guest plan, Firecracker provider, direct-init protocol, ext4 builder, OCI unpack, self-test | `runtimes/firecracker/internal/` |
| `src/externalrunner` Firecracker API, launcher, supervisor, jail, network, brokers, recovery journal, rootfs conversion, host preparation | `runtimes/firecracker/internal/` |
| `src/runnerpool` guest network planner | `runtimes/firecracker/internal/` |
| `src/runnerbootstrap` provider store, verify, GC, host checks | `runtimes/firecracker/internal/`, `internal/install/` |
| `src/internal/guesttools`, `src/cmd/lemc-guest-init`, `src/cmd/lemc-direct-init` | `runtimes/firecracker/cmd/`, `runtimes/firecracker/internal/` |
| `deploy/production/runner-seccomp.json`, `runner-apparmor.profile`, guest kernel and rootfs pins | `runtimes/firecracker/deploy/` |
| Firecracker, jailer, guest image, rootfs, network, broker, and bundle scripts | `runtimes/firecracker/scripts/` |
| `docs/RUNNER_MICROVM.md`, `RUNNER_FIRECRACKER_JAILER_LAB.md`, `RUNNER_SECURITY.md` (VM parts) | `docs/` |

### Deleted in LEMC
- `src/cmd/lemc-runner`, `src/internal/runnercmd`, the rest of
  `src/externalrunner`, `runneracceptance`, and `runneracceptancecheck`;
- the 23 Runner routes in `web/internal/handlers`, Runner identity
  credentials and sessions, and the Runner service-token audience;
- the embedded Runner in `src/platform/local_hosted_runner_*`;
- `src/runnerpool`, `src/runnerbootstrap`, and the server parts of
  `src/microvmrunner`;
- `Dockerfile.component-runner`, the Compose `runner` service, the Runner
  release lane, and `lemcli` provider and Runner commands; and
- the containerd-in-guest path and its guest binaries.

### Changed in LEMC
- The job coordinator in `src/yeschef` calls vmcp for recipes, Provider
  activations, and Builder runs.
- Runner lease tables and their leasing logic become direct dispatch
  records. This needs a goose migration.
- The System page shows `GET /v1/status`.
- `lemc-install` and Angel call `vmcp install`.

## Work Tracking
- [BACKLOG.md](BACKLOG.md) is the only work list. It holds the ordered
  items, deferred items, and decisions that are still open.
- Work on one item at a time, in order. Only the user selects a deferred
  item or a new item.
- An item that changes `../letemcook-private` must first be the one active
  phase in its `docs/PLAN.md`. Only the user selects it.
- When an item is accepted, move it to Done in BACKLOG.md with its commit.
  When a decision is settled, record it in this guide and remove it from
  BACKLOG.md.

## Go Rules
- Go is pinned to `1.26.2` in `go.mod`, `.go-version`, and the
  `Dockerfile`.
- Apply `../letemcook-private/.agents/skills/lemc-apply-google-go-style/SKILL.md`
  for all Go work. Apply
  `../letemcook-private/.agents/skills/lemc-refactor-go-safely/SKILL.md` for
  each move.
- A move must preserve behavior, errors, concurrency, cleanup, and logs.
- Keep imports in standard, external, and internal groups.
- Use clear names, explicit error handling, `context.Context`, structured
  `slog`, and tests with actionable got/want failures.
- Never concatenate quoted string literals with `+`.
- Add a dependency only when moved code already uses it or no current owner
  can do the work.

## Logging
- Use structured JSON `slog`. Emit one primary diagnostic where an error is
  handled. Wrap and return errors at lower layers.
- Use fixed safe codes and bounded facts. Correlate with the machine,
  image, snapshot, exec session, and install operation identities.
- Required failure evidence must work at production `INFO`.

## Tests And Validation
- Test a named behavior or contract. State what the test proves and which
  real failure it detects.
- Authored test inputs are HuJSON files in the owning package `testdata`,
  selected by a command-line flag. Environment variables are not a test
  configuration interface.
- Ordinary loop: run the changed package test, run one nearest boundary
  test, then run `gofmt`, `go vet ./...`, `golangci-lint run ./...`, and
  `go build ./...`. Run `shellcheck` on changed shell scripts.
- Build the image when the `Dockerfile`, the binary entry point, or the
  runtime contract changes.
- Add `-race` only for changed concurrency, cancellation, or ordering.
- Live gates need root and KVM. Never claim a live result that did not run.
- A change that affects LEMC also runs the LEMC checks named by
  `../letemcook-private/AGENTS.md`.

## Release, Versions, And Git
- Releases use `YYYYMMDDvN`. Never reuse a version for different bytes.
- LEMC pins this module and the vmcp image by exact commit and digest. Do
  not commit a `replace` to a sibling path. Use an uncommitted `go.work` for
  local work across both repositories.
- Create, move, or push a tag only with explicit user authority.
- Do not add `.github/workflows/`.
- Never force-push. Never use destructive Git commands on work you do not
  own.
- Commit messages use `type(scope): summary`.

## Working With letemcook-private
- Read `../letemcook-private/AGENTS.md` before any change there. Its rules
  apply to its files.
- Other agents may work in that repository. Use a separate worktree. Do not
  change its main checkout, branches, or worktrees that you do not own.
- When a task changes both repositories, land the vmcp change first, pin it
  in LEMC, then change LEMC.
