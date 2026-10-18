package nodes

import (
	"net"

	"christiangeorgelucas/http-tools/axiom"
	gen "christiangeorgelucas/http-tools/gen"
)

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

// CheckAddress exposes the per-account address check (address_secret_name).
func CheckAddress(raw string) (string, error) { return checkAddress(raw) }

// ResolveRequestURL exposes where a request goes: the URL, or the problem's code.
func ResolveRequestURL(ax axiom.Context, input *gen.HttpRequest) (string, string) {
	u, prob := resolveRequestURL(ax, input)
	if prob != nil {
		return "", prob.code
	}
	return u.String(), ""
}
