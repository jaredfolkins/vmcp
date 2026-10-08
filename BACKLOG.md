# Backlog

The work to do on vmcp, in order. [AGENTS.md](AGENTS.md) holds the rules
that every item follows.

## How to use this file
- Work on one item at a time, in the order of [Next](#next). Only the user
  selects an item from [Later](#later).
- Each item leaves the repository green.
- When an item is accepted, move it to [Done](#done) with its commit.
- Settle a decision in [Decisions](#decisions) before the item that needs
  it starts. Record the answer in AGENTS.md and remove it here.

## Done
- **V0 Foundation.** Guide, baked Firecracker and jailer `1.16.0`, draft
  `api`, `vmcp serve` with health and status, `Dockerfile`, and the Debian 12
  and Ubuntu 24.04 installer folders.
- **V2 Ephemeral machines.** Images, ephemeral machines, drives, events,
  stop, delete, recovery, self-test, the Go client, ownership tags, the
  posture contract, and the enforcer. The live gate and the end-to-end gate
  pass on a KVM host in the vmcp image. Commits `e737f33` to `e541a88`.
- **V2 hardening.** vmcp runs as UID 65532 with file capabilities, each
  tool and the jailer get only their own capabilities, and the AppArmor
  profile `vmcp-<install-id>` confines the service in enforce mode. The
  live gate and the end-to-end gate pass with no AppArmor denial. Commits
  `a8262bb` and `cf751c1`.

## Next
1. **V4 Install and upgrade.** `vmcp install` and the OS folder entry
   points. A caller's installer can call it. Accept: on each
   supported OS, the live gate proves a fresh install, a same-version
   reinstall, an upgrade, an injected failure that rolls back, a teardown
   that leaves only the preserved state, and a purge that leaves nothing.
   Status: `vmcp host check|install|teardown|status` (commit `5b4b833`)
   install, verify, report, and remove the host resources by ownership
   tags, also those of older versions. Their live gate passed on Ubuntu
   24.04 amd64: install, a second install, teardown of planted older
   tagged resources with untagged look-alikes left untouched, and nothing
   tagged left. Open: the service transaction (lock, quiesce, journal,
   service stop and start, verification with machines, rollback, purge,
   and preserved state), the OS folder entry points, and the live gate on
   Debian 12.
2. **V5 Persistent machines.** Root disk, drives, stop, start, restart,
   restart policy, and preservation across upgrade. Accept: live gate.
3. **V6 Exec, console, and ports.** Accept: live gate with allowed and
   denied access, and a relay test through the Go client.
4. **V7 Snapshots.** Create, list, restore, and delete. Accept: live gate,
   including a refused restore across releases.
5. **V8 Release lane.** Build, record, and publish the vmcp image with
   pinned tools. Callers consume it by digest. Declare the API stable.

## Later
- **macOS runtime with Apple `container`.** A second runtime in
  `runtimes/applecontainer/` that builds for `darwin` and drives the Apple
  [`container`](https://github.com/apple/container) CLI. Facts on
  2026-10-07: the latest release is `1.5.0`; it needs Apple silicon and
  macOS 26; its data is forward compatible only within one major version.
  Settle first:
  - how vmcp runs on macOS. It cannot use the Linux image, so it runs as a
    host process. Driving the CLI keeps vmcp free of cgo and of the
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
- Output path. Default: the caller downloads drive tars. The other option is
  a vmcp upload to a storage upstream, which avoids one copy.
- WebSocket library for exec and console. Default: `gorilla/websocket`.
  Needed by V6.
- Capacity policy. Today a slot limit (`--max-machines`) bounds machines
  and status reports host totals. Decide reservations and overcommit.
- Network identity of a persistent machine across restarts and restores.
  Needed by V5.
