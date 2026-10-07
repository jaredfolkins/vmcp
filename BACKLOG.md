# Backlog

The work to do on vmcp, in order. [AGENTS.md](AGENTS.md) holds the rules
that every item follows.

## How to use this file
- Work on one item at a time, in the order of [Next](#next). Only the user
  selects an item from [Later](#later).
- An item that changes `../letemcook-private` must first be the one active
  phase in its `docs/PLAN.md`. Only the user selects it.
- Each item leaves both repositories green.
- When an item is accepted, move it to [Done](#done) with its commit.
- Settle a decision in [Decisions](#decisions) before the item that needs
  it starts. Record the answer in AGENTS.md and remove it here.

## Done
- **V0 Foundation.** Guide, baked Firecracker and jailer `1.16.0`, draft
  `api`, `vmcp serve` with health and status, `Dockerfile`, and the Debian 12
  and Ubuntu 24.04 installer folders.

## Next
1. **V1 Remove the embedded Runner (LEMC).** Delete it and the unused
   `runnerpool` code. Accept: LEMC still runs one jailed recipe end to end.
2. **V2 Ephemeral machines (vmcp).** Implement images, create, drives,
   start, events, stop, delete, self-test, and recovery on Firecracker, with
   the ownership tags, the posture contract, and the enforcer. Add the
   `client` package and the runtime tools to the image. Accept: the
   Firecracker live gate passes in this repository with the LEMC guest
   kernel. It proves allowed and denied network access, the posture contract
   on every thread, that the enforcer kills an injected violation, and
   complete cleanup.
3. **V3 Web dispatch (LEMC).** Web runs recipes, Provider activations, and
   Builder runs through vmcp. The `vmcp` service replaces `runner`. Delete
   the Runner code and protocol. Accept: browser, LEMCSSH, and `lemcli`
   parity for one recipe with events, storage, cancel, timeout, and restart
   recovery; demo readiness passes.
4. **V4 Install and upgrade.** `vmcp install` and the OS folder entry
   points. LEMC `lemc-install` and Angel delegate to it. Accept: on each
   supported OS, the live gate proves a fresh install, a same-version
   reinstall, an upgrade, an injected failure that rolls back, a teardown
   that leaves only the preserved state, and a purge that leaves nothing.
5. **V5 Persistent machines.** Root disk, drives, stop, start, restart,
   restart policy, and preservation across upgrade. Accept: live gate.
6. **V6 Exec, console, and ports.** Accept: live gate with allowed and
   denied access, and Web relay tests.
7. **V7 Snapshots.** Create, list, restore, and delete. Accept: live gate,
   including a refused restore across releases.
8. **V8 Release lane.** Build, record, and publish the vmcp image with
   pinned tools. LEMC consumes it by digest.

LEMC product features for persistent machines, such as pages and LEMCSSH
commands, are separate LEMC phases.

## Later
- **macOS runtime with Apple `container`.** A second runtime in
  `runtimes/applecontainer/` that builds for `darwin` and drives the Apple
  [`container`](https://github.com/apple/container) CLI. Facts on
  2026-10-07: the latest release is `1.5.0`; it needs Apple silicon and
  macOS 26; its data is forward compatible only within one major version.
  Settle first:
  - how vmcp runs on macOS. It cannot use the Linux image, and LEMC allows
    only Compose services today, so a host process on macOS needs a LEMC
    rule change. Driving the CLI keeps vmcp free of cgo and of the
    virtualization entitlement, which `container` holds;
  - how to pin and install one exact `container` release, as Firecracker is
    pinned today;
  - how to enforce the vmcp network deny rules on the `container` network;
    and
  - which `api` features it supports. It must reject the others, such as
    snapshots if `container` has none, with a fixed error code.

  Accept: an installer folder under
  `runtimes/applecontainer/installers/darwin/macos/26/arm64/`, an
  owned-resource inventory, and a live gate on macOS 26 that proves allowed
  and denied network access and complete cleanup.
- **Firecracker `1.16.2`.** The latest patch of the baked line. It fixes a
  logger deadlock that can hang the VMM and its API socket, vsock and
  memory hotplug defects, and (from `1.16.1`) reverts the jailer symlink
  restriction. It changes the snapshot format. Accept: the Firecracker live
  gate passes on the new pair.
- **Debian 12 host check.** Run
  `runtimes/firecracker/installers/linux/debian/12/amd64/prepare-host.sh`
  on a real Debian 12 host with `--check` and `--apply`.
- **License.** The repository is public and has no license. The user
  selects one.

## Decisions
- Storage path. Default: Web downloads drive tars and publishes them to
  object storage. The other option is a vmcp upload to a storage upstream,
  which avoids one copy. Needed by V3.
- WebSocket library for exec and console. Default: `gorilla/websocket`,
  which LEMC already uses. Needed by V6.
- Capacity policy. Today status reports host totals. Decide reservations
  and overcommit. Needed by V2.
- Network identity of a persistent machine across restarts and restores.
  Needed by V5.
- How LEMC release builds get this module's source: vendor it, or extend
  the release source receipt to two commits. Needed by V3.
