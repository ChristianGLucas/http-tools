package nodes_test

// address_secret_name (0.9.0): a provider whose every account has its own API
// host. The person stores the address as a secret; the node sends to it only
// after checking it is a public https address, and a key is never attached to
// a request whose address failed. Each case names the bug it catches.

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	gen "christiangeorgelucas/http-tools/gen"
	"christiangeorgelucas/http-tools/nodes"
)

func TestCheckAddress(t *testing.T) {
	ok := map[string]string{
		"https://acme.api.infobip.com":        "https://acme.api.infobip.com",
		"https://ACME.api.infobip.com/":       "https://acme.api.infobip.com",   // case and trailing slash normalised
		"  https://shop.myshopify.com/api/  ": "https://shop.myshopify.com/api", // a base path is kept
	}
	for in, want := range ok {
		got, err := nodes.CheckAddress(in)
		if err != nil || got != want {
			t.Errorf("CheckAddress(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := map[string]string{
		"":                                     "empty",
		"http://acme.api.infobip.com":          "https://", // plain http would send the key in the clear
		"https://user:pw@acme.api.infobip.com": "user name",
		"https://acme.api.infobip.com:8443":    "port",
		"https://acme.api.infobip.com/?x=1":    "query",
		"https://acme.api.infobip.com/#x":      "fragment",
		"https://127.0.0.1":                    "IP address",
		"https://[::1]":                        "IP address",
		"https://169.254.169.254":              "IP address", // cloud metadata
		"https://localhost":                    "public domain",
		"https://api.localhost":                "internal",
		"https://metadata.google.internal":     "internal",
		"https://printer.local":                "internal",
		"https://acme.api.infobip.com.":        "dot",
		"https://acme_api.infobip.com":         "plain domain",
		"https://аcme.api.infobip.com":         "plain domain",  // a Cyrillic "а": a look-alike host
		"https://127.1":                        "public domain", // a numeric shorthand for loopback
		"acme.api.infobip.com":                 "https://",
	}
	for in, want := range bad {
		got, err := nodes.CheckAddress(in)
		if err == nil {
			t.Errorf("CheckAddress(%q) = %q, want a refusal (%s)", in, got, want)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("CheckAddress(%q) error %q, want it to say %q", in, err, want)
		}
		if in != "" && strings.Contains(err.Error(), strings.TrimSpace(in)) {
			t.Errorf("CheckAddress(%q) error repeats the address (a secret's value): %q", in, err)
		}
	}
}

// A request whose address fails the check never leaves the node, and so never
// carries the key: even with the dial guard lowered so loopback is reachable,
// the server sees nothing.
func TestRequest_AddressRefusedBeforeAnyKey(t *testing.T) {
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()

	for name, address := range map[string]string{
		"the test server itself (an IP literal over http)": srv.URL,
		"an https IP literal":                              "https://" + strings.TrimPrefix(srv.URL, "http://"),
		"an internal name":                                 "https://metadata.google.internal",
	} {
		ctx := newTestContext(t)
		ctx.secretsMap["ACME_SMS_ADDRESS"] = address
		ctx.secretsMap["ACME_SMS_KEY"] = "sk-secret"
		got, err := nodes.Request(context.Background(), ctx, &gen.HttpRequest{
			Url: "/sms/3/messages", Method: "POST", AddressSecretName: "ACME_SMS_ADDRESS",
			AuthType: "bearer", AuthSecretName: "ACME_SMS_KEY", TypedErrors: true,
		})
		if err != nil {
			t.Fatalf("%s: typed_errors must give an answer, got error %v", name, err)
		}
		if got.GetErrorCode() != "ADDRESS_INVALID" || !strings.Contains(got.GetError(), "ACME_SMS_ADDRESS") {
			t.Errorf("%s: got %q %q, want ADDRESS_INVALID naming the secret", name, got.GetErrorCode(), got.GetError())
		}
		if strings.Contains(got.GetError(), address) || strings.Contains(got.GetError(), "sk-secret") {
			t.Errorf("%s: the error repeats a secret's value: %q", name, got.GetError())
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the server was called %d time(s): a refused address must send nothing", n)
	}
}

// With an address, `url` is a path: an absolute url (a host the person did not
// give) is refused, not sent, before the address secret is even read.
func TestRequest_AddressRefusesAnAbsoluteURL(t *testing.T) {
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	ctx := newTestContext(t)
	ctx.secretsMap["ACME_SMS_ADDRESS"] = "https://acme.api.infobip.com"
	ctx.secretsMap["ACME_SMS_KEY"] = "sk-secret"
	for _, u := range []string{srv.URL + "/sms", "https://evil.example.com/x", "evil.example.com/x", "@evil.example.com"} {
		got, err := nodes.Request(context.Background(), ctx, &gen.HttpRequest{
			Url: u, AddressSecretName: "ACME_SMS_ADDRESS", AuthType: "bearer", AuthSecretName: "ACME_SMS_KEY",
			TypedErrors: true,
		})
		if err != nil || got.GetErrorCode() != "INVALID_URL" {
			t.Errorf("url %q with an address: got %v / %q, want INVALID_URL", u, err, got.GetErrorCode())
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the server was called %d time(s)", n)
	}
}

// An unset address secret fails like an unset auth secret: the graph needs it
// (the platform turns such a run away before it starts; this is the backstop).
func TestRequest_AddressSecretUnset(t *testing.T) {
	_, err := nodes.Request(context.Background(), newTestContext(t), &gen.HttpRequest{
		Url: "/sms/3/messages", AddressSecretName: "ACME_SMS_ADDRESS", TypedErrors: true,
	})
	if err == nil || !strings.Contains(err.Error(), `"ACME_SMS_ADDRESS" is not configured`) {
		t.Fatalf("got %v, want the unset secret named", err)
	}
}

// The streaming node takes the same address and refuses a bad one as a typed
// frame, before any request.
func TestStreamRequest_AddressRefused(t *testing.T) {
	ctx := newTestContext(t)
	ctx.secretsMap["ACME_LLM_ADDRESS"] = "https://10.0.0.7"
	frames := runStreamRequest(t, ctx, &gen.HttpRequest{
		Url: "/v1/chat/completions", Method: "POST", AddressSecretName: "ACME_LLM_ADDRESS", TypedErrors: true,
	})
	if len(frames) != 1 || frames[0].GetErrorCode() != "ADDRESS_INVALID" || !frames[0].GetIsFinal() {
		t.Fatalf("got %v, want one final ADDRESS_INVALID frame", frames)
	}
}

// The request goes to the person's address followed by the path, and no path
// can move it to another host.
func TestResolveRequestURL_AddressAndPath(t *testing.T) {
	ctx := newTestContext(t)
	ctx.secretsMap["ACME_SMS_ADDRESS"] = "https://acme.api.infobip.com/"
	ctx.secretsMap["SHOP_ADDRESS"] = "https://shop.myshopify.com/admin/api"
	cases := []struct{ name, url, want string }{
		{"ACME_SMS_ADDRESS", "/sms/3/messages", "https://acme.api.infobip.com/sms/3/messages"},
		{"ACME_SMS_ADDRESS", "", "https://acme.api.infobip.com"},
		{"ACME_SMS_ADDRESS", "//evil.example.com/x", "https://acme.api.infobip.com//evil.example.com/x"},
		{"ACME_SMS_ADDRESS", "/@evil.example.com", "https://acme.api.infobip.com/@evil.example.com"},
		{"SHOP_ADDRESS", "/orders.json", "https://shop.myshopify.com/admin/api/orders.json"},
	}
	for _, c := range cases {
		got, code := nodes.ResolveRequestURL(ctx, &gen.HttpRequest{Url: c.url, AddressSecretName: c.name})
		if code != "" || got != c.want {
			t.Errorf("%s + %q = %q (%s), want %q", c.name, c.url, got, code, c.want)
		}
	}
	// Without an address the url is used as written (0.8.0 behaviour, unchanged).
	if got, _ := nodes.ResolveRequestURL(ctx, &gen.HttpRequest{Url: "https://api.frankfurter.dev/v1/latest"}); got != "https://api.frankfurter.dev/v1/latest" {
		t.Errorf("plain url = %q", got)
	}
}
