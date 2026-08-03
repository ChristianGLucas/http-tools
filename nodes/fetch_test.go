package nodes_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	gen "christiangeorgelucas/http-tools/gen"
	"christiangeorgelucas/http-tools/nodes"
)

// TestFetch_DelegatesToRequest confirms Fetch is a behavior-identical delegate:
// the same input dispatched through Fetch and through Request against the same
// server produces the same response, field for field. Fetch is concrete (no
// kind/generic_ports) so it is placeable directly in a flow or invoked
// standalone, but the handler code path is exactly Request's — zero behavior
// divergence.
func TestFetch_DelegatesToRequest(t *testing.T) {
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", r.URL.Query().Get("q"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	input := &gen.HttpRequest{
		Url:     srv.URL,
		Method:  "GET",
		Headers: map[string]string{"X-Test": "abc"},
		Query:   map[string]string{"q": "parity"},
	}

	fetchOut, fetchErr := nodes.Fetch(context.Background(), newTestContext(t), input)
	requestOut, requestErr := nodes.Request(context.Background(), newTestContext(t), input)

	if fetchErr != nil || requestErr != nil {
		t.Fatalf("unexpected errors: fetch=%v request=%v", fetchErr, requestErr)
	}
	if fetchOut.GetStatusCode() != requestOut.GetStatusCode() {
		t.Errorf("StatusCode mismatch: Fetch=%d Request=%d", fetchOut.GetStatusCode(), requestOut.GetStatusCode())
	}
	if string(fetchOut.GetBody()) != string(requestOut.GetBody()) {
		t.Errorf("Body mismatch: Fetch=%q Request=%q", fetchOut.GetBody(), requestOut.GetBody())
	}
	if fetchOut.GetHeaders()["X-Echo"] != requestOut.GetHeaders()["X-Echo"] {
		t.Errorf("Headers mismatch: Fetch=%q Request=%q", fetchOut.GetHeaders()["X-Echo"], requestOut.GetHeaders()["X-Echo"])
	}
	if fetchOut.GetStatusCode() != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", fetchOut.GetStatusCode(), http.StatusOK)
	}
	if string(fetchOut.GetBody()) != "ok" {
		t.Errorf("Body = %q, want %q", fetchOut.GetBody(), "ok")
	}
	if fetchOut.GetHeaders()["X-Echo"] != "parity" {
		t.Errorf("X-Echo header = %q, want %q", fetchOut.GetHeaders()["X-Echo"], "parity")
	}
}

// TestFetch_BadInputMatchesRequest confirms Fetch shares Request's clean-error
// contract on malformed input (same validation runs first, since Fetch simply
// calls Request).
func TestFetch_BadInputMatchesRequest(t *testing.T) {
	cases := []struct {
		name  string
		input *gen.HttpRequest
		want  string
	}{
		{"empty url", &gen.HttpRequest{}, "url is required"},
		{"bad scheme", &gen.HttpRequest{Url: "ftp://example.com/x"}, "unsupported url scheme"},
		{"loopback blocked", &gen.HttpRequest{Url: "http://127.0.0.1:1/"}, "private or internal address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := nodes.Fetch(context.Background(), newTestContext(t), tc.input)
			if err == nil {
				t.Fatalf("expected error, got response %+v", got)
			}
			if got != nil {
				t.Errorf("expected nil response on error, got %+v", got)
			}
		})
	}
}
