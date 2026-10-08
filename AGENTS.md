# vmcp Agent Guide

## Purpose
- `vmcp` (module `github.com/jaredfolkins/vmcp`) is a VM control plane
  service. It installs, configures, upgrades, and removes one VM technology
  on its host. Its HTTP API runs and manages machines, both ephemeral and
  persistent.
- `runtimes/firecracker/` is the only runtime. Every runtime follows the
  same contract (see [Runtimes](#runtimes)).
- vmcp is its own product. It does not know, name, or depend on any
  caller. A caller is one service that holds the credential. The caller
  owns its users and its domain, and its users reach machines only through
  the caller.
- The work is not complete. Read [Current State](#current-state) and
  [BACKLOG.md](BACKLOG.md) before a change.

## User Communication
- All reports and replies must use ASD-STE100 Simplified Technical English.
- State facts, decisions, failures, and next actions with short direct
  sentences.
- Mark a claim that no executed check proves as `NOT VERIFIED`.

## Current State
- `api/` is the draft HTTP contract. Routes and fields can change until the
  first release that declares the API stable.
- `vmcp serve` implements health, status, self-test, images (create, list,
  get, delete), ephemeral machines (create, list, get, start, stop, delete),
  drive upload and download, and event streams. Persistent machines, exec,
  console, ports, and snapshots are not implemented; their routes answer
  `not_found` and a persistent spec is refused.
- The self-test boots a machine from a built-in agent-only image. The guest
  proves that the vmcp port, metadata, private and direct destinations are
  unreachable and that the egress broker refuses metadata.
- Logging and tracing follow [Logging And Tracing](#logging-and-tracing):
  `--log-level`, one request line per API call, W3C `traceparent`
  continuation, spans, and machine lifecycle lines that keep the caller
  trace.
- `client/` is the Go client. `internal/machine` is the runtime-neutral
  manager. `runtimes/firecracker` is the Firecracker runtime with its guest
  agent, image preparation, network, Go brokers, and posture checks.
- Create reserves a machine. Start provisions and boots it. A caller that
  needs launch evidence records it before start.
- vmcp runs as UID and GID `65532` with file capabilities, the AppArmor
  profile `vmcp-<install-id>` in enforce mode, and the vmcp seccomp
  profile. See [Capabilities](#capabilities).
- `vmcp host check|install|teardown|status` install, verify, report, and
  remove the host resources of one install by their ownership tags. See
  [Commands](#commands). The full V4 install transaction is not done.
- Live evidence on 2026-10-08, commit `5b4b833`, on an Ubuntu 24.04 amd64
  KVM host with kernel 7.0, AppArmor 4.0, and Docker 29, with the
  commands in
  [Container settings](#container-settings-proven-by-the-live-gate):
  - `vmcp host install --install-id live-gate` wrote and verified every
    resource. An earlier run of the same command also removed `vmcp-live`,
    a cgroup that an older vmcp version had tagged `live-gate`.
  - `TestLiveFirecracker` (runtimes/firecracker) in the vmcp image as UID
    `65532`: process I/O, image user, output drive, posture on every
    thread, egress allowed, metadata, private, direct, and host-port access
    denied, DNS, the enforcer, and complete teardown. All five subtests
    passed.
  - `TestEphemeralMachine` (e2e) and the self-test through the service,
    started by Compose with a named state volume, and the Go client:
    drives, events, redaction, egress, proof. The service used the default
    bridge network, because that host had no free Docker address pool for
    a project network. A deployment with its own networks is NOT
    VERIFIED.
  - Each Firecracker thread had UID and GID `400000`, no capability,
    `NoNewPrivs: 1`, `Seccomp: 2`, and the profile `vmcp-live-gate`.
  - The kernel log had zero `apparmor="DENIED"` lines for
    `vmcp-live-gate` during both gates, and no suppressed audit line. A
    netlink audit listener saw zero records for the profile.
  - `vmcp host teardown` removed every tagged resource, also planted older
    ones under other names and depths, killed one planted process, and
    reported five untagged look-alikes, which it did not touch. Two
    installs in a row and a teardown left nothing tagged.
- The enforcer runs in vmcp. The live gate proves that it removes a stray
  `vmcp-` tap, restores a flushed `vmcp` table, and kills a machine whose
  jail gains a setuid file or whose cgroup gains a foreign process.
- `runtimes/firecracker/release/` bakes in Firecracker `1.16.0` and jailer
  `1.16.0`, linux/amd64, verified against the upstream archive.
- `runtimes/firecracker/installers/` has Debian 12 and Ubuntu 24.04 amd64 host
  preparation scripts. Only the OS identity gate was checked, in containers.
- The remote is `git@github.com:jaredfolkins/vmcp.git`. The repository is
  public. Do not push the private data of any caller, credentials, host
  names, operator paths, or build outputs.

### Container settings proven by the live gate
Use exactly these settings. Each command below ran on 2026-10-08 with
commit `5b4b833`.

1. Build the image and install the host resources of the install, as root
   in a one-shot privileged container:

   ```bash
   docker build -t vmcp:dev .
   docker run --rm --user 0:0 --privileged --cgroupns=host --network host \
     -v /etc:/host/etc -v /lib/modules:/lib/modules:ro \
     -v /sys/fs/cgroup:/sys/fs/cgroup \
     -v /sys/kernel/security:/sys/kernel/security \
     vmcp:dev host install --install-id live-gate
   ```

2. Run vmcp with these options. Add the state volume, the credential, and
   the network of the deployment:

   ```bash
   docker run --user 65532:65532 \
     --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
     --security-opt apparmor=vmcp-live-gate \
     --security-opt seccomp=/etc/vmcp/live-gate/seccomp.json \
     --device /dev/kvm --device /dev/net/tun \
     --cap-drop ALL \
     --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add FSETID \
     --cap-add MKNOD --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE \
     --cap-add SETGID --cap-add SETUID --cap-add SYS_ADMIN \
     vmcp:dev serve --install-id live-gate
   ```

3. The Firecracker live gate runs the test binary in a gate image:
   `FROM vmcp:dev` with the output of
   `CGO_ENABLED=0 go test -c -trimpath ./runtimes/firecracker` at
   `/usr/local/bin/vmcp`, with the file capabilities of vmcp
   (`setcap cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_net_admin,cap_net_bind_service=eip`),
   and `runtimes/firecracker/testdata/live.hujson` at
   `/usr/share/vmcp/live.hujson`. The same profile and capabilities then
   apply. Run it with the options of step 2, `--no-healthcheck` (the image
   healthcheck would run the test binary), and the arguments
   `-test.run '^TestLiveFirecracker$' -test.v -vmcp-live-config /usr/share/vmcp/live.hujson`.

4. The end-to-end gate runs `vmcp serve` with the options of step 2, a
   named volume at `/var/lib/vmcp`, the credential `.e2e/vmcp-credential`
   at `/run/secrets/vmcp-credential`, and, for this local gate only, the
   port on `127.0.0.1:18081`. Then it runs
   `go test ./e2e -run TestEphemeralMachine -vmcp-e2e-config testdata/e2e.hujson`.

5. Count the denials of each gate:
   `sudo journalctl -k --since <start> | grep 'apparmor="DENIED"' | grep -c 'profile="vmcp-<install-id>"'`
   must print `0`. The same window must have no
   `kauditd_printk_skb: ... callbacks suppressed` line, because a
   suppressed line can hide a denial.

6. `vmcp host teardown --install-id live-gate` with the options of step 1
   removes the install.

Do not set `no-new-privileges`: it stops the kernel from granting file
capabilities, and vmcp then refuses to start. `systempaths=unconfined`,
`SYS_CHROOT`, and `SYS_RESOURCE` are not needed; the gates passed without
them. Docker's default seccomp profile blocks the jailer `pivot_root`.

vmcp must not be PID 1. With `--new-pid-ns` the jailer exits after it starts
Firecracker, so Firecracker is reparented to PID 1, and vmcp does not reap
processes that it did not start. The image runs `tini` as PID 1. Without it,
each machine leaves a zombie Firecracker process. Do not add `--init`.

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

### The caller owns
- Its users, accounts, authorization, scheduling, and persistence.
- The decision to create, start, stop, attach to, expose, snapshot, or
  delete each machine.
- The mapping from its own work to a `MachineSpec`.
- The meaning of guest output, and where drive contents are stored.
- All user access. The caller authorizes each user and relays consoles,
  exec sessions, events, and ports.
- The decision to install or upgrade vmcp.

### Neutrality rules
- vmcp never imports, names, or documents a caller. Callers import `api`
  and `client`.
- Do not add caller domain concepts to vmcp, such as jobs, tasks, leases,
  accounts, or users. Use machine, image, drive, file, upstream, port,
  snapshot, label, and event.
- A caller-driven need enters vmcp only as a general machine feature with
  its own tests. Caller plans and migration notes stay in the caller's
  repository.
- Labels are opaque caller data. vmcp stores and filters them. It never
  interprets them.
- Tokens in a request are opaque. Only host brokers use them. A token never
  enters a guest and is never returned or logged.
- No database, queue, or object-store client in vmcp.

## The API
- HTTP/1.1 with JSON bodies. Drive content is a tar body. Events are
  newline-delimited JSON. Exec and console attach use WebSocket.
- Every route except `GET /health` and `GET /ready` needs
  `Authorization: Bearer <credential>`. `GET /ready` answers 204 when the
  runtime is ready and 503 when it is not, with no body. The credential is
  one owner-private file. One caller holds it. vmcp compares credential
  hashes in constant time.
- vmcp listens only on the private service network that it shares with its
  caller. Never publish its port on a host interface.
- Errors use `api.ErrorResponse` with a fixed `api.ErrorCode` and a safe
  message.
- Secrets: `process.secret_env` entries and `secret` files are never stored
  and never written to host disk. The host sends them to the guest agent
  over vsock in one message after the agent's Hello. Secret files must be
  under `/run`, a guest tmpfs. The record keeps only secret entry names.
  Each secret value of 8 bytes or more is redacted from events, also when it
  is split across output chunks.
- A create with an existing `name` and the same spec returns the existing
  machine. A different spec with the same name is a conflict.
- Every machine event has a sequence number. A caller resumes a stream with
  `after`.
- `api/api.go` lists the draft routes. The server registers a route only
  when a backlog item implements it with its tests.

### Change rules
- A change to an exported identifier, route, or JSON field in `api` is an
  API change. Record it in the release notes. Callers pin vmcp by commit,
  so they choose when to take it.
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
- Exec and console: the caller creates an exec session or attaches to the
  serial console, authorizes each user, and relays the WebSocket. Log the
  session start and end, not its content.
- Ports: vmcp exposes a guest port only on the service network. The machine
  response lists each endpoint. The caller authorizes and proxies user
  traffic.
- Snapshots: vmcp pauses the guest, saves memory, device state, and disk,
  and resumes it. Restore needs a stopped machine and the same runtime
  release that made the snapshot. Restore replaces the machine state in
  place. Do not clone a snapshot into a second machine.

### Recovery
- When vmcp stops, it stops every running ephemeral machine. Each gets state
  `failed`, the detail `vmcp stopped`, a proof, and an exit event that ends
  its event streams.
- When vmcp starts, it destroys every ephemeral guest that an earlier
  process left. Each one gets state `failed`, exit reason `failed`, and a
  proof.
- Persistent machines follow their restart policy.
- A prepared image records the compatibility key of the guest agent and
  unpacker that built it. An image with another key never boots: vmcp
  drops it at start, prepares it again on the next request for its
  reference, and refuses a new machine for it. It keeps an image that a
  live machine uses.
- After a caller restart, the caller lists machines by label and
  reconciles them with its own records.

## Caller Integration
A caller uses vmcp in this order. Each step is a general API feature.

| Need | vmcp feature |
| --- | --- |
| Readiness | `GET /ready`; details from `GET /v1/status` |
| Host proof | `POST /v1/selftest` |
| Image | `POST /v1/images` with a digest-pinned reference and a registry upstream |
| Launch evidence before boot | Create the machine, record the evidence, then start |
| Input files | Upload drive tars before start |
| Output | Follow `GET /v1/machines/{id}/events`; download writable drives after the exit |
| Guest access to services | `network.upstreams`, with `allow_write` for writes; tokens stay on the host |
| Secrets in guest output | `redactions` |
| Cancel and limits | Stop or delete; `timeout_seconds`; `output_limit_bytes` |
| Cleanup proof | `api.Proof` in the final machine record |
| Reconciliation after a restart | Labels and `GET /v1/machines?label=key=value` |
| Correlation | One W3C `traceparent` per unit of work |

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
- vmcp runs without `no_new_privs`, because the container
  `no-new-privileges` option stops the kernel from granting file
  capabilities. Firecracker sets `no_new_privs` on each of its threads when
  it installs its seccomp filters; the posture check proves it. `vmcp
  serve` refuses to start without its capabilities. Its error names
  `no-new-privileges` when that option is set.
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
- vmcp runs as UID and GID `65532` with file capabilities, the vmcp
  seccomp profile, and the AppArmor profile `vmcp-<install-id>`. Only
  development may run as root and unconfined.
- Firecracker and the jailer are baked in. `runtimes/firecracker/release/` holds the
  gzip binaries and `release-v1.json`, the lock with the upstream archive URL
  and SHA-256 and each binary's size, SHA-256, and mode. vmcp writes a binary
  only after its size and SHA-256 match the lock. Never download at install
  or run time.
- The image extracts the jailer from the baked release at build time and
  sets its file capabilities. vmcp uses `/usr/libexec/vmcp/jailer` only
  after its size, SHA-256, and file capabilities match, and it refuses a
  jailer on a `nosuid` file system, which ignores file capabilities.
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
- The image installs `iproute2`, `nftables`, `e2fsprogs`, CA certificates,
  `tini`, `apparmor` and `kmod` (for `vmcp host`), and `libcap2-bin`, and
  fetches the pinned guest kernel by SHA-256. It creates the user `vmcp`
  (`65532:65532`), removes every setuid and setgid bit, owns
  `/var/lib/vmcp` by `65532` with mode `0700`, sets the file capabilities
  in [Capabilities](#capabilities), and runs as `USER 65532:65532`. Pin the
  package versions in the release lane (V8). The build arguments
  `VMCP_VERSION` and `VMCP_COMMIT` go into the install receipt.
- Run `vmcp host install --install-id <id>` before the service starts.
  Run `vmcp host teardown --install-id <id>` after the service is removed
  for good. See [Commands](#commands).
- A Compose deployment runs vmcp as one service. It needs:
  - `user: "65532:65532"`;
  - `cap_drop: [ALL]` and `cap_add` `CHOWN`, `DAC_OVERRIDE`, `FOWNER`,
    `FSETID`, `MKNOD`, `NET_ADMIN`, `NET_BIND_SERVICE`, `SETGID`,
    `SETUID`, and `SYS_ADMIN`;
  - `security_opt` `apparmor=vmcp-<id>` and
    `seccomp=/etc/vmcp/<id>/seccomp.json`, and not `no-new-privileges`.
    That option stops the kernel from granting the file capabilities of
    vmcp and the jailer, and vmcp then refuses to start;
  - `cgroup: host`, a read-write bind of `/sys/fs/cgroup`, and the devices
    `/dev/kvm` and `/dev/net/tun`;
  - a named volume at `/var/lib/vmcp`. A new named volume takes the owner
    `65532` and mode `0700` from the image. A bind mount needs that owner
    and mode;
  - the credential file at `/run/secrets/vmcp-credential`, owned by `65532`
    with mode `0400`. The caller mounts its own copy;
  - only the private network that it shares with its caller, a network for
    guest egress, and no `ports`;
  - no `init`: `tini` in the image is PID 1; and
  - the image healthcheck `vmcp healthcheck`.
- One vmcp serves one caller on one host. Multi-host is a later decision.

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

Today `vmcp host install` does the host part of steps 1, 5, 6, and 8: it
checks the host, tears down the tagged host resources, writes the host
configuration, verifies it from a fresh inventory, and writes its receipt.
The service steps are V4 work.

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
every other service on the host are not vmcp-owned.

### Failure and rollback
- A failure before teardown leaves the host unchanged.
- A failure after teardown starts automatic rollback: tear down the failed
  attempt, then install the last committed release and configuration with
  the same transaction, and restart the recorded persistent machines.
- If rollback also fails, leave vmcp torn down with only the preserved
  state. Never leave a partly installed vmcp serving. Report both failures,
  the first failed check, and the cleanup result.

### Commands
- `vmcp host check|install|teardown|status --install-id <id>` manage the
  host resources of one install. Each prints one JSON result on stdout and
  exits with status 1 when `ok` is false. The command line is decoded
  strictly. An unknown command, flag, or argument fails before any host
  access.
  - `check` verifies root, the host `/etc` mount, cgroup v2 with `cpu`,
    `memory`, and `pids` on at the root, AppArmor, and CPU virtualization.
    It makes no change.
  - `install` runs `check`, then `teardown`, then writes
    `/etc/vmcp/<id>/seccomp.json`, writes `/etc/apparmor.d/vmcp-<id>` and
    loads it with `apparmor_parser -r -W` in enforce mode, creates the
    parent cgroup `vmcp-<id>`, tags it, enables `cpu`, `memory`, and
    `pids`, and delegates it (the directory, `cgroup.procs`,
    `cgroup.subtree_control`, and `cgroup.threads`) to the service user,
    loads `kvm`, `kvm_intel` or `kvm_amd`, and `tun` and writes
    `/etc/modules-load.d/vmcp-<id>.conf`, and verifies all of it from a
    fresh inventory. It writes `/etc/vmcp/<id>/receipt.json` (schema,
    install ID, vmcp version and commit, Firecracker release, service UID
    and GID, time) last. A second `install` tears down and rebuilds.
    `--service-uid` and `--service-gid` (default `65532`) select the
    service user. It refuses to start when an untagged or foreign resource
    has one of its names.
  - `teardown` removes every resource with the install tag. It kills the
    processes of owned cgroups with `cgroup.kill`, waits, and reports them
    in `killed_processes`. It removes cgroups children first, unloads and
    removes profile files, and removes module files, configuration
    directories, and host links. It refuses an owned directory that holds
    an untagged file. It never touches an untagged resource, a resource of
    another install, Docker objects, OS packages, or a loaded kernel
    module. It reports them in `conflicts` and `other_installs`. Then it
    verifies from a fresh inventory that nothing tagged is left.
  - `status` prints the tagged inventory, the conflicts, the other
    installs, and the receipt.
- Run them as root from the vmcp image in a one-shot privileged container.
  `--host-root` (default `/host`) holds the host `/etc`. The host network
  namespace lets teardown find host links, `/sys/kernel/security` lets
  `apparmor_parser` load profiles, and `/lib/modules` lets `modprobe` load
  modules:

  ```bash
  docker run --rm --user 0:0 --privileged --cgroupns=host --network host \
    -v /etc:/host/etc -v /lib/modules:/lib/modules:ro \
    -v /sys/fs/cgroup:/sys/fs/cgroup \
    -v /sys/kernel/security:/sys/kernel/security \
    <vmcp image> host install --install-id <id>
  ```

- Stop the vmcp service of the install before `install` or `teardown`.
  Teardown kills each process that it finds in an owned cgroup.
- The log has one JSON line per step on stderr with `install_op` and
  `install_id`. Spans: `host.<command>`, `host.check`, `host.inventory`,
  `host.teardown`, `host.write.config`, `host.write.apparmor`,
  `host.write.cgroup`, `host.write.modules`, and `host.verify`. `INFO`:
  `host command started`, `host resource written`, `host resource
  removed`, and `host command finished`. `WARN` codes: `host_conflict`,
  `host_check_failed`, and `host_processes_killed`. `ERROR` codes:
  `host_teardown_incomplete` and `host_<command>_failed`.
- Not done (V4): `vmcp check`, `vmcp install`, `vmcp teardown`, `vmcp
  purge` (with an explicit confirmation flag), and `vmcp status` of the
  full transaction above, with the lock, quiesce, journal, service stop
  and start, verification with machines, rollback, and preserved state.
  Each will write one JSON result. Configuration will be one JSON file
  decoded strictly.
- An operator runs the OS folder entry point with root. Only that path may
  install a missing OS package.
- A caller's installer may call `vmcp host install` and, later, `vmcp
  install`. It first stops creating machines and waits until no ephemeral
  machine exists. An automatic upgrade does not change OS packages.

## Runtime Security

### Ownership tags
- Tag every host resource that vmcp creates with its install identity:
  - cgroups: the `trusted.vmcp.owner` extended attribute on the parent
    cgroup `vmcp-<install-id>`. A cgroup inside a tagged cgroup, such as a
    machine cgroup, belongs to the same install unless it has another tag;
  - host text files: the first line `# vmcp-owner: <install-id>`, as in
    `/etc/apparmor.d/vmcp-<install-id>` and
    `/etc/modules-load.d/vmcp-<install-id>.conf`;
  - host JSON files: the marker `/etc/vmcp/<install-id>/.vmcp-owner`. Its
    first line is the owner line. Each other line names one file of that
    directory that vmcp wrote, such as `seccomp.json` and `receipt.json`;
  - AppArmor: the profile name `vmcp-<install-id>`;
  - state-root files: an owner marker in the state root and in each jail
    root;
  - network: the `vmcp-` name prefix and an `ifalias` of
    `vmcp:<install>:<machine>` on each tap and veth device. vmcp creates
    them in its container network namespace; teardown also scans the host
    network namespace;
  - nftables: the one `vmcp` table, with the machine ID in each rule
    comment.
- Inventory, teardown, and status find resources by these tags, never by
  the names that the current version writes. So teardown also removes what
  older versions created. vmcp deletes only tagged resources. It reports an
  untagged resource with a vmcp name, or a resource of another install, and
  does not touch it.
- An install identity is 1 to 32 lowercase letters, digits, and inner
  hyphens.

### Capabilities
vmcp runs as UID `65532`. Each process gets only the capabilities in this
table. The live gate proved each set: without a listed capability, the gate
fails, except where the notes below say otherwise.

| Process | Capabilities | Source |
| --- | --- | --- |
| `tini` | none | |
| `vmcp` | `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `NET_ADMIN`, `NET_BIND_SERVICE` | file capabilities `=eip` on `/usr/local/bin/vmcp` |
| `ip` and `nft` that change state, `nft` listings | `NET_ADMIN` | ambient set |
| `ip` link listings | none | |
| `mke2fs` | `DAC_OVERRIDE` | ambient set |
| jailer | `CHOWN`, `DAC_OVERRIDE`, `MKNOD`, `SETGID`, `SETUID`, `SYS_ADMIN` | file capabilities `=ep` on `/usr/libexec/vmcp/jailer` |
| Firecracker | none | |

- The container capability set is the union of the file capabilities. A
  file capability that is not in the container set makes the exec fail.
- Do not give the jailer ambient capabilities. A jailer that runs as UID
  `65532` keeps them across its UID change and gives them to Firecracker.
  The file capabilities of the jailer clear the ambient set, so Firecracker
  starts with none.
- vmcp needs `DAC_OVERRIDE` also to open `/dev/kvm`, which hosts often own
  by `root:kvm` with mode `0660`.
- `FSETID` keeps the setgid bits of image files whose group vmcp is not in.
  The gate image has no such file, so the gate does not prove it.
- `NET_BIND_SERVICE` lets the DNS broker bind port 53. Docker sets
  `net.ipv4.ip_unprivileged_port_start=0` in a container network
  namespace, so the gate also passed without it. vmcp keeps it, so that
  the broker does not depend on that setting.
- The jailer writes `+cpu`, `+memory`, and `+pids` into
  `cgroup.subtree_control` of each ancestor of its cgroup, also of the
  root. The profile allows that one root file.

### Posture contract
After boot, every thread of a jailed Firecracker process must have:
the machine UID and GID (`--uid-base` plus the machine slot, never the
vmcp UID `65532`); zero effective, permitted, and ambient capabilities;
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
- Follow [Never log](#never-log). Clear secret bytes after use. Apply
  `redactions` before an event leaves vmcp.
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
cmd/vmcp/                           serve, healthcheck, and host commands
internal/server/                    HTTP server and authentication
internal/trace/                     W3C trace context, spans, and the log handler
internal/install/                   teardown-first install transaction (V4)
runtimes/firecracker/               Firecracker runtime (linux)
runtimes/firecracker/release/       baked Firecracker and jailer, lock, licenses
runtimes/firecracker/installers/<kernel>/<distribution>/<version>/<arch>/
runtimes/firecracker/cmd/           guest binaries (V2)
runtimes/firecracker/internal/      jail, launch, network, brokers, rootfs, guest (V2)
runtimes/firecracker/deploy/        seccomp profile and AppArmor profile template
Dockerfile                          Linux service image
docs/                               design, security, and ADRs
```
- Create a package only when a backlog item moves or writes code into it. Do
  not create empty packages or placeholders.
- Do not create `util`, `common`, `shared`, `helpers`, or `types` packages
  or package-per-file layouts.

## Work Tracking
- [BACKLOG.md](BACKLOG.md) is the only work list. It holds the ordered
  items, deferred items, and decisions that are still open.
- Work on one item at a time, in order. Only the user selects a deferred
  item or a new item.
- When an item is accepted, move it to Done in BACKLOG.md with its commit.
  When a decision is settled, record it in this guide and remove it from
  BACKLOG.md.

## Go Rules
- Go is pinned to `1.26.2` in `go.mod`, `.go-version`, and the
  `Dockerfile`.
- Follow the [Google Go style guide](https://google.github.io/styleguide/go/)
  and its decisions and best practices.
- A refactor or move must preserve behavior, errors, concurrency, cleanup,
  and logs. Prove it with the tests of the moved behavior before and after.
- Keep imports in standard, external, and internal groups.
- Use clear names, explicit error handling, `context.Context`, structured
  `slog`, and tests with actionable got/want failures.
- Never concatenate quoted string literals with `+`.
- Add a dependency only when moved code already uses it or no current owner
  can do the work.

## Logging And Tracing
The vmcp log is the debugging record. A person who reads only the log must
be able to answer: what did the caller ask, what did vmcp do, how long did
each step take, what is the state now, and why did it fail. Every change
keeps that true.

### Format
- One JSON object per line from `slog` to stderr. The container runtime
  keeps it as the vmcp log. `vmcp serve --log-level` selects the minimum
  level: `debug`, `info` (the default), `warn`, or `error`.
- The logger is `trace.NewHandler` over the JSON handler. It adds
  `trace_id` and `span_id` to each record whose context carries a span.
  Log with the `slog` `Context` methods. Never add trace attributes by hand.
- Every `WARN` and `ERROR` line has a fixed `code`. A failure line has an
  `error` attribute with the cause, cut by `trace.BoundedError`.
- Use these attribute names: `machine`, `machine_name`, `image`,
  `snapshot`, `exec_session`, `install_op`, `install_id`, `drive`,
  `upstream`, `route`,
  `status`, `duration_ms`, and `code`. Durations are milliseconds from
  `trace.Millis`.

### Levels
- `ERROR`: an operation failed and an operator must act, or a security
  control fired. Examples: an internal API error, a teardown that left a
  resource, an enforcer or posture violation, a restored `vmcp` table, and
  a failed self-test run.
- `WARN`: a recoverable or caller-caused failure, or a degraded state.
  Examples: a rejected credential, an image, provision, or boot failure, a
  failed self-test result, an output limit, a failed teardown step, a
  machine failed by a vmcp restart, and a failed upstream request.
- `INFO`: lifecycle and every API call. Examples: start and stop with the
  configuration, one line per API request, image prepared or deleted,
  machine created, started, guest agent connected, ended, and deleted,
  recovery, the self-test result, and each refused guest destination.
- `DEBUG`: each step and its duration. Examples: span lines, provisioning
  steps, the jailer start, posture, kill, allowed egress, upstream
  responses, drive transfers, and health and readiness probes.
- Required failure evidence works at `INFO`. `DEBUG` explains the steps.
  Do not log the same failure at every layer. Wrap and return errors; log
  once where the error is handled.

### Tracing
- Each API request runs in a span. vmcp continues the caller's W3C
  `traceparent` header (`api.HeaderTraceparent`) and starts a new trace when
  the header is missing or invalid. Each response returns the request span
  in `traceparent`. The Go client sends the value from
  `client.WithTraceparent`, and `client.Error.TraceID` names the vmcp trace
  of a failed call.
- The request line (`msg` `api request`) is the record of the request
  span: route, status, bytes, duration, error code, and cause.
- Work that outlives the request (boot, the guest process, timeouts,
  teardown, brokers, and enforcer actions on the machine) logs with
  `trace.Detach` of the request context. Its lines keep the trace of the
  request that created or started the machine.
- Start a span with `trace.Start` for each step that can fail or that takes
  more than about 10 ms. `Span.End` writes one `DEBUG` line with the span
  name, parent, duration, and outcome.
- Background work without a caller (startup recovery, enforcer sweeps)
  starts its own trace.
- A caller should send one trace per unit of its own work. One `trace_id`
  then finds that work in the caller log and in the vmcp log.

### New features
- A change that adds a route, a runtime operation, a broker, an install
  step, or a background loop names in the same change: its spans, its
  `INFO` lifecycle lines, its `WARN` and `ERROR` codes, and its
  correlation attributes.
- Its boundary test captures the log of the main flow and of the main
  failure. It checks the levels, the codes, and that the lines carry the
  caller trace. `internal/server/logging_test.go` is the example.
- Review question: can a person find and explain a failure of each new
  step from the log at `INFO`, and see each step with its duration at
  `DEBUG`?

### Never log
- Tokens, credentials, request or response bodies, environment values,
  secret files, drive or file contents, exec or console content, or guest
  output.
- Guest-supplied text, such as a guest host name, path, or drive name, in
  raw form. Log only checked values (see `logHost`) or vmcp's own names.
- An error that wraps any of these. Build errors from safe facts only, and
  strip URLs with queries from network errors before logging.

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

## Release, Versions, And Git
- Releases use `YYYYMMDDvN`. Never reuse a version for different bytes.
- `scripts/release-image.sh <YYYYMMDDvN> <commit>` builds the image of one
  pushed commit from the public repository with that version and commit,
  and publishes it to `ghcr.io/jaredfolkins/vmcp` under the version and
  `sha-<commit>` tags. It refuses a version that is already published.
  Callers pin the printed digest.
- Callers pin this module and the vmcp image by exact commit and digest.
  Do not commit a `replace` directive. Use an uncommitted `go.work` for
  local work with a caller.
- Never commit build outputs. `.gitignore` lists them.
- Create, move, or push a tag only with explicit user authority.
- Do not add `.github/workflows/`.
- Never force-push. Never use destructive Git commands on work you do not
  own.
- Commit messages use `type(scope): summary`.
