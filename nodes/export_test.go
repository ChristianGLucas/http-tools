package nodes

import "net"

// This file is compiled only under `go test`. It exposes internal seams to the
// external nodes_test package so tests can exercise the happy path (which would
// otherwise be refused by the loopback SSRF guard) and unit-test the address
// predicate directly — without giving production code any way to weaken the
// guard.

// IsBlockedIP exposes the address predicate for direct table testing.
func IsBlockedIP(ip net.IP) bool { return isBlockedIP(ip) }

// SetBlockIPForTest swaps the dial-time guard and returns a restore function.
// Use it to allow a loopback test server for one test, then defer the restore.
func SetBlockIPForTest(f func(net.IP) bool) (restore func()) {
	old := blockIP
	blockIP = f
	return func() { blockIP = old }
}
