// Package firecracker is the Firecracker runtime of vmcp.
//
// It bakes in one known Firecracker and jailer release. The binaries and
// their lock are embedded from the release directory. An install writes
// them only after their size and SHA-256 match the lock. Nothing is
// downloaded at install or run time.
package firecracker
