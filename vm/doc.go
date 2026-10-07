// Package vm is the public API of the VM control plane.
//
// A Backend runs machines with one VM technology on one host. Each machine
// is a fresh isolated guest that runs one process and is then destroyed. The
// firecracker package is the only backend.
//
// A caller uses one Backend like this:
//
//  1. At startup, call Status, then Recover, then SelfTest.
//  2. For each run, optionally call PrepareRootFS and cache the result.
//  3. Call Create. The machine is provisioned and isolated but not booted.
//  4. Call Start. Read Events until the channel closes.
//  5. Call Wait for the exit.
//  6. Call Destroy on every path: success, failure, cancellation, timeout,
//     and lost caller state. Destroy returns the teardown proof.
//
// This package does not know the caller's domain. It has no jobs, leases,
// accounts, or output vocabulary. Tokens are opaque strings that only host
// brokers use. They never enter a guest.
//
// The API is a draft. It is not implemented yet. The extraction plan in
// AGENTS.md validates it against the current LEMC Runner before code moves.
package vm
