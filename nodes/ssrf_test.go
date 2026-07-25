package nodes_test

import (
	"context"
	"net"
	"strings"
	"testing"

	gen "christiangeorgelucas/http-tools/gen"
	"christiangeorgelucas/http-tools/nodes"

	"net/http"
	"net/http/httptest"
)

// These tests close the SSRF-hardening gaps the address-predicate table did not
// cover: (1) a redirect whose next hop is a private/metadata target, (2) the
// connect-time resolved-IP validation that makes the guard DNS-rebinding
// resistant (it checks the dialed IP, not the URL hostname), and (3) the
// IPv4-mapped-IPv6 form that slips a loopback/metadata address past a naive
// string or To16-only check.

// TestRequest_RedirectToPrivateIsBlockedPerHop proves the guard re-validates
// EVERY hop, not just the first URL. The first hop is a loopback test server
// standing in for a "public" origin (permitted via the test seam); it 302s to a
// cloud-metadata address, which must be refused at the redirect hop's dial.
func TestRequest_RedirectToPrivateIsBlockedPerHop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	// Permit only the loopback test server (the stand-in public first hop); the
	// real predicate still governs everything else, so the metadata redirect
	// target stays blocked. This isolates "was the REDIRECT HOP re-validated?".
	restore := nodes.SetBlockIPForTest(func(ip net.IP) bool {
		if ip.IsLoopback() {
			return false
		}
		return nodes.IsBlockedIP(ip)
	})
	defer restore()

	_, err := nodes.Request(context.Background(), newTestContext(t), &gen.HttpRequest{
		Url: srv.URL, Method: "GET", FollowRedirects: true,
	})
	if err == nil {
		t.Fatal("redirect to 169.254.169.254 must be refused, got no error")
	}
	if !strings.Contains(err.Error(), "private or internal address") {
		t.Errorf("want SSRF refusal on the redirect hop, got %v", err)
	}
}

// TestRequest_ValidatesResolvedIPNotHostname proves the guard checks the
// CONNECT-TIME resolved IP (net.Dialer.Control) rather than the URL hostname
// string — the property that defeats DNS rebinding, since there is no
// check-then-connect window to race. A hostname that resolves to a private
// address must be refused even though the hostname is not itself a literal IP.
func TestRequest_ValidatesResolvedIPNotHostname(t *testing.T) {
	// "localhost" resolves to loopback (127.0.0.1 / ::1). With the real guard the
	// dial is refused before any connection is attempted.
	_, err := nodes.Request(context.Background(), newTestContext(t), &gen.HttpRequest{
		Url: "http://localhost/", Method: "GET",
	})
	if err == nil {
		t.Fatal("a hostname resolving to loopback must be refused, got no error")
	}
	if !strings.Contains(err.Error(), "private or internal address") {
		t.Errorf("want SSRF refusal for hostname->private, got %v", err)
	}
}

// TestRequest_IPv4MappedIPv6Blocked pins the IPv4-mapped-IPv6 bypass:
// ::ffff:127.0.0.1 is loopback and ::ffff:169.254.169.254 is the metadata
// address wearing an IPv6 coat. A guard that only inspects the 16-byte form (or
// the hostname string) would miss them; isBlockedIP normalizes via To4().
func TestRequest_IPv4MappedIPv6Blocked(t *testing.T) {
	for _, u := range []string{
		"http://[::ffff:127.0.0.1]/",
		"http://[::ffff:169.254.169.254]/",
	} {
		_, err := nodes.Request(context.Background(), newTestContext(t), &gen.HttpRequest{
			Url: u, Method: "GET",
		})
		if err == nil {
			t.Fatalf("%s (IPv4-mapped private) must be refused, got no error", u)
		}
		if !strings.Contains(err.Error(), "private or internal address") {
			t.Errorf("%s: want SSRF refusal, got %v", u, err)
		}
	}
}

// TestRequest_RedirectCountBounded pins that a redirect loop cannot spin
// unbounded — the guard stops after maxRedirects even when every hop is
// otherwise permitted (loopback allowed via the seam here).
func TestRequest_RedirectCountBounded(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/next", http.StatusFound) // infinite self-redirect
	}))
	defer srv.Close()
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false }) // allow loopback
	defer restore()

	_, err := nodes.Request(context.Background(), newTestContext(t), &gen.HttpRequest{
		Url: srv.URL, Method: "GET", FollowRedirects: true,
	})
	if err == nil {
		t.Fatal("an infinite redirect loop must error, not hang or succeed")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Errorf("want a redirect-bound error, got %v", err)
	}
}
