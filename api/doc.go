// Package api is the HTTP contract of the vmcp service.
//
// vmcp runs machines with one VM technology on one host. A machine is
// either ephemeral or persistent:
//
//   - An ephemeral machine runs one process in a fresh guest. vmcp destroys
//     the guest when the process stops. Writable drives stay readable until
//     the caller deletes the machine.
//   - A persistent machine keeps its disk and drives. The caller can stop,
//     start, restart, snapshot, restore, attach to, and expose ports of it.
//
// The caller flow for one ephemeral run is:
//
//  1. Prepare the image once with RouteCreateImage.
//  2. Create the machine. vmcp provisions and isolates it but does not boot
//     it.
//  3. Upload input drives with RoutePutDrive.
//  4. Start the machine and follow RouteMachineEvents until the exit event.
//  5. Download writable drives with RouteGetDrive.
//  6. Delete the machine. The response has the teardown proof.
//
// Requests and responses are JSON unless a route says otherwise. Every
// route except RouteHealth needs the bearer credential. Tokens inside a
// request, such as an upstream token, are opaque to vmcp and never enter a
// guest.
//
// The contract is a draft. Routes and fields can change until a caller
// uses them in production.
package api
