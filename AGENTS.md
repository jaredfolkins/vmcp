# VM Control Plane Agent Guide

## Purpose
- `vmcp` (module `github.com/jaredfolkins/vmcp`) is a small VM control
  plane for one VM technology per backend. It installs, configures,
  upgrades, and removes that technology on a host. It runs and manages machines: create, start, stream, wait,
  destroy, recover, self-test, and status.
- `firecracker/` is the only backend. More backends can follow. Each one
  satisfies the same contract (see [Backends](#backends)).
- The control plane does not know its callers' domains. LEMC
  (`../letemcook-private`) is the first caller. LEMC's `lemc-runner` leases
  jobs and links this module as a Go library to run each job in one machine.
- The code comes from LEMC. The extraction is not complete. Read
  [Current State](#current-state) and [Extraction Plan](#extraction-plan)
  before a change.

## User Communication
- All reports and replies must use ASD-STE100 Simplified Technical English.
- State facts, decisions, failures, and next actions with short direct
  sentences.
- Mark a claim that no executed check proves as `NOT VERIFIED`.

## Current State
- Present: this guide, `go.mod`, the draft `vm` API, the baked Firecracker
  release, and the Firecracker host preparation scripts under
  `firecracker/installers/`.
- `firecracker/release/` bakes in Firecracker `1.16.0` and jailer `1.16.0`,
  linux/amd64, from the official upstream archive. The archive matches the
  GitHub asset digest and the published `.sha256.txt`. Both binaries match
  the archive `SHA256SUMS`. `go test ./firecracker` proves that the
  embedded bytes match the lock.
- LEMC still ships `1.12.0`. The LEMC jailer lab document records a passed
  `hosted-runner-lab` jailer proof with official `1.16.0` on this host. The
  lab did not keep its binaries, so byte identity with that run is
  `NOT VERIFIED`. A guest boot with the LEMC guest kernel and rootfs on
  `1.16.0` is `NOT VERIFIED`. Run the Firecracker live gate before LEMC
  adopts this pair.
- `vm/` is a draft. It has no implementation and no caller. Phase C2
  validates it against the current LEMC Runner before code moves.
- `firecracker/installers/linux/ubuntu/24.04/amd64/prepare-host.sh` is a
  copy of the LEMC script with neutral messages. The Debian 12 script is the
  same script with the Debian identity. The OS identity gate of each script
  was checked in a container. The package, device, and Docker checks are
  `NOT VERIFIED` on a real Debian 12 host.
- All VM code is still in `../letemcook-private`.
- The remote is `git@github.com:jaredfolkins/vmcp.git`. The repository is
  public. Do not push private LEMC data, credentials, host names, or
  operator paths.

## Scope And Budget
- Do the selected phase task and its acceptance checks. Then stop.
- Do not start a later phase, an adjacent cleanup, or a new framework
  without explicit user direction.
- Repair the first failing owner. Do not add a fallback, retry, alias, or
  second path to avoid a failure.
- Reuse evidence that is already in context. Do not repeat broad searches or
  checks without a changed input.
- Report an unrelated defect briefly. Leave it unchanged. Lint repairs are
  always allowed.

## Ownership Boundary

### The control plane owns
- The public `vm` API and its caller flow.
- The install transaction, its lock, journal, receipt, rollback, and the
  `vmcp` command.
- The rule set that every backend must satisfy.

### Each backend owns
- Machine provisioning, boot, process start, events, exit, and destroy.
- Isolation: jail, cgroups, guest network, brokers, drives, and cleanup.
- Recovery of machines that an earlier process left.
- Root filesystem preparation from OCI images.
- Its release bundle. For Firecracker: Firecracker, jailer, guest kernel,
  guest base rootfs, and guest tools.
- Its OS installer folders, its owned-resource inventory, and its live gate.

### The caller owns
For LEMC, `lemc-runner` and the LEMC server own:

- jobs, leases, heartbeats, accounts, authorization, and tokens;
- the LEMC control-plane protocol and the LEMC job-stream vocabulary;
- the mapping from a job to a `vm.Spec`;
- workspace hydration, storage publication, and object keys;
- caching of root filesystem artifacts; and
- scheduling, the job hold, and the decision to install or upgrade.

### Neutrality rules
- This module never imports LEMC. LEMC imports this module.
- Do not add caller concepts to this module: no job, lease, task, account,
  recipe, Cookbook, Provider, verb, or object key. Use machine, run, drive,
  file, upstream, and event.
- Tokens are opaque strings. Only host brokers use them. A token never
  enters a guest.
- No database, queue, object-store, or Docker-socket client in this module.
  Brokers forward only to the exact upstreams in the spec.

## The API

### Go library
- `vm` is the public API. `firecracker` implements `vm.Backend`. The caller
  imports the backend it uses. Do not add a backend registry or plugin
  loader.
- Caller flow:
  1. At startup: `Status`, then `Recover`, then `SelfTest`.
  2. For each run: optional `PrepareRootFS`, then `Create`. The machine is
     provisioned and isolated but not booted.
  3. `Start`. Read `Events` until the channel closes. `Wait` for the exit.
  4. `Destroy` on every path. It returns the teardown proof.
- The split between `Create` and `Start` lets a caller record launch
  evidence before a guest boots. LEMC needs this for ADR 0043 in LEMC.
- The library runs inside the caller's process. That process holds the KVM
  and network privileges that the backend needs.

### Install command
- `vmcp` is one static Linux binary. Commands: `check`, `install`,
  `teardown`, `purge`, and `status`. It selects the backend with
  `--backend` and reads one JSON configuration file.
- Each command writes one JSON result to stdout.
- LEMC's `lemc-install` and Angel call `vmcp` for the VM technology. They
  must not prepare, change, or remove backend-owned host resources
  themselves.

### API change rules
- A change to an exported identifier in `vm` or a backend package is an API
  change. Update this module and its callers in one coordinated change.
- Do not keep an old and a new API shape at the same time without a named
  compatibility range and a removal condition.
- A new backend must not change the caller flow.
- Keep interfaces small. Add a method only when a current caller needs it.

### How LEMC maps to the API
| LEMC Runner today | With the control plane |
| --- | --- |
| Provider verify and jailed self-test at startup | `Backend.Status`, `Backend.SelfTest` |
| Recovery journal at startup | `Backend.Recover`; the caller reports the proofs |
| Rootfs prewarm and conversion | `Backend.PrepareRootFS`; LEMC uploads and caches the artifact |
| `provision-jail` before guest boot | `Create`; LEMC records the step; then `Start` |
| Registry proxy, pull-only or builder-push | `Network.Upstreams` with `AllowWrite` |
| Guest events through the control proxy to LEMC | `Machine.Events`; `lemc-runner` classifies and forwards |
| Workspace hydration and storage publication | `Spec.Drives`; LEMC fills and reads the host directories |
| Provider activation guest with a Secret | One more machine with a secret `File` |
| Secret redaction of guest output | `Spec.Redactions` |
| Cancel, timeout, lost heartbeat | Context cancel, `Spec.Timeout`, `Destroy` |
| `JobProof` | `vm.Proof`; LEMC adds its object keys |

## Backends
- Each backend lives in one top-level directory named for its technology,
  such as `firecracker/`.
- A backend is supported only after all of these exist:
  1. an implementation of `vm.Backend` that passes the shared rules;
  2. at least one OS installer folder;
  3. an owned-resource inventory that teardown and `status` use; and
  4. a passing live gate on each listed OS.
- A backend must enforce every rule in [Runtime Security](#runtime-security)
  with its own mechanism.
- Firecracker rules:
  - Always use the jailer. Run each guest with a non-root UID and GID, a
    chroot, cgroup v2 limits, rlimits, and a new PID namespace.
  - Production runs as UID and GID `65532` with file capabilities, a seccomp
    profile, and an AppArmor profile. Only development may run as root and
    unconfined.
  - Firecracker and the jailer are baked in. `firecracker/release/` holds
    the gzip binaries and `release-v1.json`, the lock with the upstream
    archive URL and SHA-256 and each binary's size, SHA-256, and mode. The
    package embeds them with `go:embed`. Every binary that links this module
    carries the same pair. Install writes a binary only after its size and
    SHA-256 match the lock. Never download at install or run time.
  - Firecracker and the jailer always come from the same upstream release.
    Never mix versions.
  - Keep upstream `LICENSE`, `NOTICE`, and `THIRD-PARTY` from the same
    archive next to the binaries. Apache-2.0 requires them for
    redistribution.
  - To change the pair: download the official archive, verify its SHA-256,
    extract only `firecracker-v<version>-x86_64` and `jailer-v<version>-x86_64`,
    check them against the archive `SHA256SUMS`, compress each with
    `gzip -n` (the current files reproduce byte for byte this way), update
    the lock and the license files, run
    `go test ./firecracker`, and pass the Firecracker live gate.
  - LEMC keeps its own pin until it links this module in C3, or until the
    user selects a LEMC phase that adopts this pair. Do not change the LEMC
    pin from this repository.
  - The guest kernel, guest base rootfs, and guest tools are not baked in
    yet. LEMC still pins and builds them.
- All backends and the control plane stay in one Go module. Split a backend
  into its own Go module only when its dependencies conflict with the rest.

## Host Install, Configuration, And Upgrade

### Supported hosts
| Backend | OS | Version | Architecture | Folder |
| --- | --- | --- | --- | --- |
| firecracker | Debian | 12 | amd64 | `firecracker/installers/linux/debian/12/amd64/` |
| firecracker | Ubuntu | 24.04 | amd64 | `firecracker/installers/linux/ubuntu/24.04/amd64/` |

- The folder path is
  `<backend>/installers/<kernel>/<distribution>/<version>/<arch>/`. Use the
  `ID` and `VERSION_ID` values from `/etc/os-release`.
- Firecracker hosts need systemd as PID 1, CPU virtualization flags,
  cgroup v2, and read-write `/dev/kvm` and `/dev/net/tun`. LEMC adds its own
  full-stack host requirements, such as rootful Docker.
- A folder holds only facts and steps that differ by OS: package names,
  package-manager commands, kernel module names, and security-profile
  support. The OS-neutral transaction belongs to `vmcp`.
- A new OS target needs its folder and a passing install live gate on that
  OS. Do not list it as supported before that gate passes.
- arm64 is not supported. The Firecracker bundle and live gates are amd64
  only.

### Install always tears down first
Every install runs the same transaction. A first install, a reinstall, an
upgrade, a downgrade, a rollback, and a configuration change all use it.
There is no in-place update or reconfigure path. Do not skip teardown when
the version is unchanged.

1. **Preflight.** Verify the OS folder matches the host, the host
   prerequisites, the exact input digests, and the configuration. Make no
   change. Stop on the first failure and name the correction.
2. **Lock.** Take the install lock. One transaction at a time.
3. **Quiesce.** Require that no machine exists. See
   [Preconditions](#preconditions).
4. **Record intent.** Write the target release and configuration to the
   journal before the first mutation.
5. **Teardown.** Remove every backend-owned resource except the preserved
   upgrade state. Verify removal from a fresh inventory. The journal is not
   proof of removal.
6. **Install.** Write the baked binaries and the other release artifacts
   from verified local inputs. Write backend-owned host configuration. Prepare the parent cgroup and
   the state root. Only an operator-run install from the OS folder may
   install a missing OS package; it does this before step 1.
7. **Verify.** Run `SelfTest`. Run one machine, verify cleanup, run a second
   machine, and check that no machine resource remains.
8. **Commit.** Write the install receipt only after step 7 passes. Release
   the lock.

### Preserved upgrade state
Teardown keeps only this state, in one install directory under the backend
state root:

- the operator configuration that was the input of the last install;
- the install receipt and journal of the last committed install; and
- the release artifacts of the last committed install, verified against its
  receipt. A new `vmcp` embeds only its own release, so rollback restores
  these copies. Replace them when the next install commits.

All other backend state is disposable. A cache is not upgrade state. The
caller's own state, such as the LEMC Runner identity credential, belongs to
the caller.

### Removed on every install
Teardown removes each of these that the backend created:

- jailer and Firecracker processes, jail chroots, and API sockets;
- the parent cgroup and every machine cgroup;
- network namespaces, veth and tap devices, routes, and nftables rules;
- mounts, listeners, broker processes, and broker files;
- the installed release bundle and its active pointer;
- scratch, rootfs, drive, and prepared-rootfs cache files;
- recovery records and self-test markers; and
- backend-owned host configuration files, such as kernel module persistence
  and the loaded AppArmor profile.

Teardown deletes only resources that it can prove the backend owns. It never
adopts, re-owns, or recursively deletes unowned or conflicting state. It
stops and reports the conflict.

### Not backend-owned
- OS packages, Docker Engine, the kernel, firmware, DNS, storage, and the
  host firewall policy. The OS folder may install a missing prerequisite.
  Teardown never removes one.
- The caller's processes, containers, and state.

### Preconditions
- Teardown starts only when no machine exists. The backend inventory is the
  authority. Do not destroy a running machine to make teardown possible.
- The caller stops new work first. For a LEMC update, that is the LEMC job
  hold (ADR 0038 in LEMC). Do not use the LEMC retirement drain for an
  upgrade. It cancels queued jobs.

### Failure and rollback
- A failure before teardown leaves the host unchanged.
- A failure after teardown starts automatic rollback: tear down the failed
  attempt, then install the release and configuration from the last
  committed receipt with the same transaction. Verify it the same way.
- If rollback also fails, leave the backend torn down with only the
  preserved state. Never leave a partly installed backend in use. Report
  both failures, the first failed check, and the cleanup result.
- Validate configuration in preflight. A configuration error after teardown
  is a failure.

### Commands
- `check`: preflight only. No change.
- `install`: the full transaction.
- `teardown`: steps 1 to 5 with no reinstall. Keeps the preserved state.
- `purge`: teardown, then remove the preserved state. Needs an explicit
  confirmation flag.
- `status`: read-only inventory of the installed release, configuration
  digest, and backend-owned resources.
- Decode configuration strictly: reject unknown fields, duplicate keys, and
  invalid values.

### Who runs it
- An operator runs the OS folder entry point on the host with root.
- LEMC's `lemc-install` calls `vmcp` for the VM part of a full-stack install.
- LEMC's update owner (Angel) holds jobs, stops `lemc-runner`, calls
  `vmcp install` with the selected release, and then starts the matching
  `lemc-runner`. An automatic upgrade does not change OS packages. If a
  release needs a new OS prerequisite, preflight fails and names the OS
  folder to run.
- `vmcp` is a command, not a daemon. Within LEMC, every service still runs
  in the canonical Docker Compose project.

## Runtime Security
- Use one fresh isolated guest per machine. Destroy it on success, failure,
  cancellation, timeout, or loss of the caller.
- A guest can reach only its brokers: DNS, policy-controlled public egress,
  and the exact upstreams in its spec.
- Deny guest access to host loopback, host and private networks, cloud
  metadata, container bridges, and every other host service.
- Never expose a Docker socket, host networking, host PID namespace, host
  root, broad mounts, or catch-all NAT to a guest.
- Never log arbitrary error text, tokens, request bodies, secret file
  bodies, private file contents, or raw guest output. Clear secret bytes
  after use. Apply `Spec.Redactions` before an event leaves the backend.
- A change to a backend, networking, brokers, install, teardown, cleanup,
  or credentials needs that backend's Linux/KVM live gate. Unit tests do not
  replace it.
- A live gate proves allowed behavior, denied reachability, terminal state,
  and removal of every owned process, jail, cgroup, namespace, tap, rule,
  mount, socket, listener, scratch path, and drive.

## Target Layout
```text
vm/                                 public API
cmd/vmcp/                           install command
internal/install/                   teardown-first install transaction
firecracker/                        Firecracker backend, implements vm.Backend
firecracker/installers/<kernel>/<distribution>/<version>/<arch>/
firecracker/release/                baked Firecracker and jailer, lock, licenses
firecracker/cmd/                    guest binaries and the bundle build tool
firecracker/internal/               jail, launch, network, brokers, rootfs, guest
firecracker/deploy/                 pins, seccomp, AppArmor
firecracker/scripts/                guest image, rootfs, and bundle build
docs/                               design, security, and ADRs
```
- Create a package only when a phase moves code into it. Do not create
  empty packages or placeholders.
- Do not create `util`, `common`, `shared`, `helpers`, or `types` packages
  or package-per-file layouts.

## Source Map
Paths on the left are in `../letemcook-private`.

| Source | Target | Note |
| --- | --- | --- |
| `src/microvmrunner`, VM half: guest plan, Firecracker provider, direct-init protocol, ext4 builder, OCI unpack, self-test | `firecracker/internal/` | Server-only proof stores, resolver, fallback policy, image-ready GC, and server result decode stay in LEMC. |
| `src/externalrunner` VM side: Firecracker API, launcher, supervisor, jail, network, brokers, recovery journal, rootfs conversion, host preparation | `firecracker/internal/` | Lease, heartbeat, material, events, storage, and finish code stays in LEMC `lemc-runner`. |
| `src/runnerpool` guest network planner | `firecracker/internal/` | `ActualState` and profiles stay in LEMC. |
| `src/runnerbootstrap` provider bundle store, verify, GC, snapshots, host checks | `firecracker/internal/`, `internal/install/` | Compose preflight stays in LEMC `lemc-install`. |
| `src/internal/guesttools`, `src/cmd/lemc-guest-init`, `src/cmd/lemc-direct-init` | `firecracker/cmd/`, `firecracker/internal/` | Remove LEMC verb classification and storage upload from the guest. |
| `src/cmd/lemc-provider-release-input` | `firecracker/cmd/` | |
| `deploy/production/provider-inputs-v1.json` `firecracker` entry and the generated bundle's `firecracker` and `jailer` | `firecracker/release/` | Baked at `1.16.0`. LEMC stays at `1.12.0` until it adopts this pair. |
| `deploy/production/provider-inputs-v1.json` other entries, `runner-seccomp.json`, `runner-apparmor.profile` | `firecracker/deploy/` | |
| Firecracker, jailer, guest image, rootfs, network, broker, and provider bundle scripts | `firecracker/scripts/` | Python brokers stay until ADR 0022 in LEMC is decided. |
| `installers/linux/ubuntu/24.04/amd64/prepare-host.sh` | `firecracker/installers/` | Copied. Remove the LEMC copy in C4. |
| `docs/RUNNER_MICROVM.md`, `RUNNER_FIRECRACKER_JAILER_LAB.md`, `RUNNER_SECURITY.md` (VM parts) | `docs/` | Keep LEMC ADR numbers in references. |

Stays in LEMC: `lemc-runner` as the adapter (lease loop, heartbeat,
runtime material, event classification, storage publication, finish), the
server side of its protocol, `jobstream`, `runneracceptance`, Builder and
Provider orchestration, the Runner image, and `lemc-install`.

Delete in LEMC instead of moving:

- the embedded Runner in `src/platform/local_hosted_runner_*` and its start
  call in `web/internal/server/web.go`. Both Compose files disable it;
- the `lemcli` Firecracker smoke worker and provider commands, after their
  proof moves to the Firecracker live gate;
- the containerd-in-guest path (`lemc-guest-agent`, `lemc-containerd-run`,
  `lemc-artifact-sync`, `lemc-log-sync`, `guestcontainerd`) when no
  consumer remains; and
- the unused `runnerpool` EC2 adapter, reconciler, upgrade plan, and
  destroy plan.

## Extraction Plan
- Each phase that changes `../letemcook-private` must first be the one
  active phase in its `docs/PLAN.md`. Only the user selects it.
- Do one phase at a time. Each phase leaves both repositories green and one
  jailed Firecracker recipe working end to end through LEMC.

1. **C0 Foundation.** Repository, this guide, the draft `vm` API, the
   baked Firecracker and jailer, and the Firecracker installer folders.
   Done.
2. **C1 Remove the second Runner.** In LEMC, delete the embedded Runner,
   the smoke worker, and the unused `runnerpool` code. Remove the
   containerd-in-guest path if no consumer remains. Accept: LEMC runs one
   jailed recipe through the external Runner only.
3. **C2 Cut the seam inside LEMC.** Refactor `lemc-runner` so that all VM
   work goes through one in-repo package with the `vm` API shape. Keep
   every LEMC concept on the adapter side: guest events reach `lemc-runner`
   instead of the LEMC events route; classification runs on the host;
   storage moves through drives; Provider and Builder runs are ordinary
   machines with files and upstreams. Finalize the `vm` API from this
   work. Accept: the VM package imports no LEMC package; the LEMC
   server API is unchanged; the Firecracker live gate passes.
4. **C3 Move the VM code.** Move the VM package, guest binaries, bundle
   build, scripts, pins, and docs here. `lemc-runner` imports this module
   by exact commit. LEMC deletes the moved code. Accept: this module
   builds and tests alone; the live gate passes here; LEMC demo readiness
   passes.
5. **C4 Install command.** Build `vmcp` and the OS folder entry points.
   LEMC `lemc-install` and Angel delegate the VM part to it. Accept: on
   each supported OS, the live gate proves a fresh install, a same-version
   reinstall, an upgrade, an injected failure that rolls back, a teardown
   that leaves only the preserved state, and a purge that leaves nothing.
6. **C5 Release lane.** This repository builds the Firecracker release
   bundle and `vmcp` with pinned tools. LEMC consumes them by digest.
   Accept: one LEMC candidate passes the final-image jailed self-test with
   the bundle from this repository.

## Open Decisions
Ask the user before a phase depends on one of these.

- Firecracker and the jailer are decided: they are baked into this module.
  `lemc-runner` and `vmcp` must link the same module commit. `Status`
  reports the baked and the installed release, and readiness fails on a
  mismatch.
- Whether to bake in the guest kernel, guest base rootfs, and guest tools
  the same way. They are large (about 11 MB and 171 MB compressed for the
  kernel and rootfs). Today LEMC pins them and the LEMC Runner image
  contains them.
- How LEMC release builds get this module's source. Today a release source
  receipt covers one repository. Options: vendor the module into LEMC, or
  extend the source receipt to two commits.
- Guest output classification moves from the guest to `lemc-runner` on the
  host. LEMC must confirm that this keeps its output exposure rules and its
  live event ordering.
- Where the shared leaf code goes: redaction, exact-secret redaction, and
  the HuJSON test-config reader. Default: this module keeps its own
  internal copy of what it uses.

## Go Rules
- Go is pinned to `1.26.2` in `go.mod` and `.go-version`.
- Apply `../letemcook-private/.agents/skills/lemc-apply-google-go-style/SKILL.md`
  for all Go work. Apply
  `../letemcook-private/.agents/skills/lemc-refactor-go-safely/SKILL.md` for
  each move.
- A move must preserve behavior, errors, concurrency, cleanup, logs, and
  packaging.
- Keep imports in standard, external, and internal groups.
- Use clear names, explicit error handling, `context.Context`, structured
  `slog`, and tests with actionable got/want failures.
- Never concatenate quoted string literals with `+`.
- Add a dependency only when moved code already uses it or no current owner
  can do the work.

## Logging
- Use structured `slog`. Emit one primary diagnostic where an error is
  handled. Wrap and return errors at lower layers.
- Use fixed safe codes and bounded facts. Correlate with the backend,
  machine, and install operation identities. Log a caller's `Spec.Name`
  only as a label.
- Required failure evidence must work at production `INFO`.

## Tests And Validation
- Test a named behavior or contract. State what the test proves and which
  real failure it detects.
- Authored test inputs are HuJSON files in the owning package `testdata`,
  selected by a command-line flag. Environment variables are not a test
  configuration interface. Reject unknown fields and invalid values before
  starting fixtures.
- Ordinary loop: run the changed package test, run one nearest boundary
  test, then run `gofmt`, `go vet ./...`, lint, and `go build ./...`.
- Run `shellcheck` on every changed shell script.
- Add `-race` only for changed concurrency, cancellation, or ordering.
- Live gates need root and KVM. Never claim a live result that did not run.
- A change that affects LEMC also runs the LEMC checks named by
  `../letemcook-private/AGENTS.md`.

## Release, Versions, And Git
- Releases use `YYYYMMDDvN`. Never reuse a version for different bytes.
- LEMC pins this module by exact commit. Do not commit a `replace` to a
  sibling path. Use an uncommitted `go.work` for local work across both
  repositories.
- Create, move, or push a tag only with explicit user authority.
- Do not add `.github/workflows/`.
- Never force-push. Never use destructive Git commands on work you do not
  own.
- Commit messages use `type(scope): summary`, for example
  `feat(install): tear down before install`.

## Working With letemcook-private
- Read `../letemcook-private/AGENTS.md` before any change there. Its rules
  apply to its files.
- Other agents may work in that repository. Use a separate worktree. Do not
  change its main checkout, branches, or worktrees that you do not own.
- When a phase changes both repositories, land the control-plane change
  first, pin it in LEMC, then change LEMC.
