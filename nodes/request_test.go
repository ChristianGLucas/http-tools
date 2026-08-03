package nodes_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"christiangeorgelucas/http-tools/axiom"
	gen "christiangeorgelucas/http-tools/gen"
	"christiangeorgelucas/http-tools/nodes"
)

// testContext is a testing.T-backed axiom.Context for unit tests. Populate
// secretsMap with any secrets your node needs during the test, or
// revokedNames (ADR-156) to exercise a revoked secret via
// axiom.Secrets.Status.
type testContext struct {
	t            *testing.T
	secretsMap   map[string]string
	revokedNames map[string]bool
}

func newTestContext(t *testing.T) *testContext {
	return &testContext{t: t, secretsMap: map[string]string{}, revokedNames: map[string]bool{}}
}

// testLogger forwards log output to testing.T so it is captured per-test.
type testLogger struct{ t *testing.T }

func (l *testLogger) Debug(msg string, args ...any) { l.t.Logf("DEBUG  %s %v", msg, args) }
func (l *testLogger) Info(msg string, args ...any)  { l.t.Logf("INFO   %s %v", msg, args) }
func (l *testLogger) Warn(msg string, args ...any)  { l.t.Logf("WARN   %s %v", msg, args) }
func (l *testLogger) Error(msg string, args ...any) { l.t.Logf("ERROR  %s %v", msg, args) }

// testSecrets is a simple in-memory axiom.Secrets backed by testContext.secretsMap.
type testSecrets struct {
	m       map[string]string
	revoked map[string]bool
}

func (s testSecrets) Get(name string) (string, bool) { v, ok := s.m[name]; return v, ok }

func (s testSecrets) Status(name string) axiom.SecretStatus {
	if _, ok := s.m[name]; ok {
		return axiom.SecretStatusAvailable
	}
	if s.revoked[name] {
		return axiom.SecretStatusRevoked
	}
	return axiom.SecretStatusUnset
}

// testFlowReflection is an empty running-flow view — no graph in a unit test.
// Override its methods (via a custom axiom.FlowReflection) in a specific test
// if your node reads ax.Reflection().Flow() (ADR-050/055).
type testFlowReflection struct{}

func (testFlowReflection) Nodes() []axiom.ReflectionNode     { return nil }
func (testFlowReflection) Edges() []axiom.ReflectionEdge     { return nil }
func (testFlowReflection) LoopEdges() []axiom.ReflectionEdge { return nil }
func (testFlowReflection) Position() axiom.FlowPosition      { return axiom.FlowPosition{} }
func (testFlowReflection) GraphID() string                   { return "" }

type testReflection struct{}

func (testReflection) Flow() axiom.FlowReflection { return testFlowReflection{} }

// testFlowMutation is a no-op mutation sink. If your node is mutation-capable,
// replace it with a recorder you assert on to verify it called AddNode/AddEdge
// with the expected package + condition (ADR-051/054).
type testFlowMutation struct{}

func (testFlowMutation) AddNode(_, _, _ string, _ *axiom.CanvasPosition) uint32 { return 0 }
func (testFlowMutation) AddEdge(_, _ uint32, _ *axiom.EdgeCondition)         {}

type testMutation struct{}

func (testMutation) Flow() axiom.FlowMutation { return testFlowMutation{} }

func (c *testContext) Log() axiom.Logger            { return &testLogger{c.t} }
func (c *testContext) Secrets() axiom.Secrets       { return testSecrets{c.secretsMap, c.revokedNames} }
func (c *testContext) ExecutionID() string          { return "test-execution-id" }
func (c *testContext) FlowID() string               { return "test-flow-id" }
func (c *testContext) TenantID() string             { return "test-tenant-id" }
func (c *testContext) Reflection() axiom.Reflection { return testReflection{} }
func (c *testContext) Mutation() axiom.Mutation     { return testMutation{} }

// TESTS — delete this block when done ─────────────────────────────────────────
// Tests are required to push this package. The push pipeline runs your
// tests as a quality gate — a package will not be pushed if tests fail or
// do not meet the minimum requirements.
//
// Requirements checked before pushing:
//   - At least one test per node
//   - All tests must pass
//   - Output fields must be meaningfully asserted — not just error-checked
//
// The generated test below is a starting point. Replace the TODO comment with
// real assertions that verify your node returns correct data for known inputs.
// Think: given a specific input, what should the output fields contain?
//
// Run your tests locally at any time:
//   axiom test

// TestRequest_HappyPath exercises the full request/response path against a
// local test server. Loopback is normally refused by the SSRF guard, so the
// test seam permits it for the duration of this test only.
func TestRequest_HappyPath(t *testing.T) {
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if got := r.Header.Get("X-Test"); got != "abc" {
			t.Errorf("X-Test header = %q, want abc", got)
		}
		if got := r.URL.Query().Get("q"); got != "42" {
			t.Errorf("query q = %q, want 42", got)
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"echo":%q}`, string(body))
	}))
	defer srv.Close()

	got, err := nodes.Request(context.Background(), newTestContext(t), &gen.HttpRequest{
		Url:     srv.URL,
		Method:  "POST",
		Headers: map[string]string{"X-Test": "abc"},
		Query:   map[string]string{"q": "42"},
		Body:    []byte("hello"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.GetStatusCode() != http.StatusCreated {
		t.Errorf("StatusCode = %d, want %d", got.GetStatusCode(), http.StatusCreated)
	}
	if want := `{"echo":"hello"}`; string(got.GetBody()) != want {
		t.Errorf("Body = %q, want %q", string(got.GetBody()), want)
	}
	if ct := got.GetHeaders()["Content-Type"]; ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if got.GetFinalUrl() == "" {
		t.Error("FinalUrl is empty")
	}
}

// TestRequest_BadInput asserts that malformed or unsafe requests fail cleanly
// with an actionable error — never a leaked stack or a partial response. The
// SSRF cases run with the real guard in place.
func TestRequest_BadInput(t *testing.T) {
	cases := []struct {
		name  string
		input *gen.HttpRequest
		want  string
	}{
		{"empty url", &gen.HttpRequest{}, "url is required"},
		{"bad scheme", &gen.HttpRequest{Url: "ftp://example.com/x"}, "unsupported url scheme"},
		{"file scheme", &gen.HttpRequest{Url: "file:///etc/passwd"}, "unsupported url scheme"},
		{"bad method", &gen.HttpRequest{Url: "https://example.com", Method: "TRACE"}, "unsupported HTTP method"},
		{"loopback blocked", &gen.HttpRequest{Url: "http://127.0.0.1:1/"}, "private or internal address"},
		{"metadata blocked", &gen.HttpRequest{Url: "http://169.254.169.254/latest/meta-data/"}, "private or internal address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := nodes.Request(context.Background(), newTestContext(t), tc.input)
			if err == nil {
				t.Fatalf("expected error, got response %+v", got)
			}
			if got != nil {
				t.Errorf("expected nil response on error, got %+v", got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

// TestIsBlockedIP pins the address predicate: public routable addresses pass,
// everything private/internal is refused.
func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", "0.0.0.0", "100.64.0.1", "fe80::1", "fc00::1",
		"224.0.0.1", "::ffff:127.0.0.1",
	}
	for _, s := range blocked {
		if !nodes.IsBlockedIP(net.ParseIP(s)) {
			t.Errorf("IsBlockedIP(%s) = false, want true (should be blocked)", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1::"}
	for _, s := range allowed {
		if nodes.IsBlockedIP(net.ParseIP(s)) {
			t.Errorf("IsBlockedIP(%s) = true, want false (should be allowed)", s)
		}
	}
}

// TestRequest_AuthBearer confirms auth_type="bearer" resolves the named
// secret via ax.secrets and sends it as a standard Authorization header —
// the config carries only the secret NAME, never the value.
func TestRequest_AuthBearer(t *testing.T) {
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx := newTestContext(t)
	ctx.secretsMap["MY_API_KEY"] = "s3cr3t-value"

	got, err := nodes.Request(context.Background(), ctx, &gen.HttpRequest{
		Url:            srv.URL,
		AuthType:       "bearer",
		AuthSecretName: "MY_API_KEY",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.GetStatusCode() != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", got.GetStatusCode(), http.StatusOK)
	}
	if want := "Bearer s3cr3t-value"; gotAuth != want {
		t.Errorf("Authorization header = %q, want %q", gotAuth, want)
	}
}

// TestRequest_AuthHeader confirms auth_type="header" sets the caller-named
// header to the resolved secret value.
func TestRequest_AuthHeader(t *testing.T) {
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()

	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx := newTestContext(t)
	ctx.secretsMap["SVC_KEY"] = "hdr-secret"

	_, err := nodes.Request(context.Background(), ctx, &gen.HttpRequest{
		Url:            srv.URL,
		AuthType:       "header",
		AuthSecretName: "SVC_KEY",
		AuthHeaderName: "X-API-Key",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "hdr-secret"; gotHeader != want {
		t.Errorf("X-API-Key header = %q, want %q", gotHeader, want)
	}
}

// TestRequest_AuthHeaderWithPrefix confirms auth_type="header" with a
// non-empty auth_value_prefix prepends the literal prefix (trailing space and
// all) to the resolved secret — the DeepL/Shippo/Token/ApiKey scheme shape —
// while the config still carries only the secret NAME, never its value.
func TestRequest_AuthHeaderWithPrefix(t *testing.T) {
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()

	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx := newTestContext(t)
	ctx.secretsMap["DEEPL_API_KEY"] = "abc-123"

	_, err := nodes.Request(context.Background(), ctx, &gen.HttpRequest{
		Url:             srv.URL,
		AuthType:        "header",
		AuthSecretName:  "DEEPL_API_KEY",
		AuthHeaderName:  "Authorization",
		AuthValuePrefix: "DeepL-Auth-Key ",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "DeepL-Auth-Key abc-123"; gotHeader != want {
		t.Errorf("Authorization header = %q, want %q", gotHeader, want)
	}
}

// TestRequest_AuthHeaderEmptyPrefixUnchanged confirms an empty
// auth_value_prefix preserves the 0.2.0 behavior exactly (raw secret value).
func TestRequest_AuthHeaderEmptyPrefixUnchanged(t *testing.T) {
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()

	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx := newTestContext(t)
	ctx.secretsMap["SVC_KEY"] = "hdr-secret"

	_, err := nodes.Request(context.Background(), ctx, &gen.HttpRequest{
		Url:            srv.URL,
		AuthType:       "header",
		AuthSecretName: "SVC_KEY",
		AuthHeaderName: "X-API-Key",
		// AuthValuePrefix intentionally unset.
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "hdr-secret"; gotHeader != want {
		t.Errorf("X-API-Key header = %q, want %q (empty prefix must send raw value)", gotHeader, want)
	}
}

// TestRequest_AuthQueryRedacted confirms auth_type="query" places the
// resolved secret as a query parameter on the OUTBOUND request, but the
// value never appears in the node's own returned FinalUrl — it must come
// back redacted.
func TestRequest_AuthQueryRedacted(t *testing.T) {
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()

	var gotParam string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotParam = r.URL.Query().Get("api_key")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx := newTestContext(t)
	ctx.secretsMap["QUERY_KEY"] = "qp-secret"

	got, err := nodes.Request(context.Background(), ctx, &gen.HttpRequest{
		Url:            srv.URL,
		AuthType:       "query",
		AuthSecretName: "QUERY_KEY",
		AuthParam:      "api_key",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotParam != "qp-secret" {
		t.Errorf("server saw api_key = %q, want %q", gotParam, "qp-secret")
	}
	if strings.Contains(got.GetFinalUrl(), "qp-secret") {
		t.Errorf("FinalUrl leaked the secret value: %q", got.GetFinalUrl())
	}
	if !strings.Contains(got.GetFinalUrl(), "api_key=REDACTED") {
		t.Errorf("FinalUrl = %q, want redacted api_key param", got.GetFinalUrl())
	}
}

// TestRequest_AuthErrors covers the clean-error paths for auth config: an
// unresolvable secret, missing required companion fields, and an unknown
// auth_type. None of these may leak a secret value into the error message.
func TestRequest_AuthErrors(t *testing.T) {
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()

	cases := []struct {
		name  string
		input *gen.HttpRequest
		want  string
	}{
		{
			name: "secret not configured",
			input: &gen.HttpRequest{
				Url: "https://example.com", AuthType: "bearer", AuthSecretName: "NOPE",
			},
			want: `required secret "NOPE" is not configured`,
		},
		{
			name: "missing secret name",
			input: &gen.HttpRequest{
				Url: "https://example.com", AuthType: "bearer",
			},
			want: "auth_secret_name is required",
		},
		{
			name: "missing header name",
			input: &gen.HttpRequest{
				Url: "https://example.com", AuthType: "header", AuthSecretName: "K",
			},
			want: "auth_header_name is required",
		},
		{
			name: "missing query param",
			input: &gen.HttpRequest{
				Url: "https://example.com", AuthType: "query", AuthSecretName: "K",
			},
			want: "auth_param is required",
		},
		{
			name: "unknown auth_type",
			input: &gen.HttpRequest{
				Url: "https://example.com", AuthType: "basic", AuthSecretName: "K",
			},
			want: "unsupported auth_type",
		},
	}

	ctx := newTestContext(t)
	ctx.secretsMap["K"] = "should-never-appear-in-any-error"

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := nodes.Request(context.Background(), ctx, tc.input)
			if err == nil {
				t.Fatalf("expected error, got response %+v", got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.want)
			}
			if strings.Contains(err.Error(), "should-never-appear-in-any-error") {
				t.Errorf("error leaked secret value: %q", err.Error())
			}
		})
	}
}

// TestRequest_DualHeaderCarriers confirms the second auth carrier (auth_*_2)
// resolves an independent named secret and sets a second header alongside the
// primary — the two-credential shape of Datadog (DD-API-KEY + DD-APPLICATION-KEY)
// and Alpaca. Each carrier's config carries only its secret NAME, never a value.
func TestRequest_DualHeaderCarriers(t *testing.T) {
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()

	var gotAPI, gotApp string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPI = r.Header.Get("DD-API-KEY")
		gotApp = r.Header.Get("DD-APPLICATION-KEY")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx := newTestContext(t)
	ctx.secretsMap["DATADOG_API_KEY"] = "api-secret"
	ctx.secretsMap["DATADOG_APP_KEY"] = "app-secret"

	got, err := nodes.Request(context.Background(), ctx, &gen.HttpRequest{
		Url:              srv.URL,
		AuthType:         "header",
		AuthSecretName:   "DATADOG_API_KEY",
		AuthHeaderName:   "DD-API-KEY",
		AuthType_2:       "header",
		AuthSecretName_2: "DATADOG_APP_KEY",
		AuthHeaderName_2: "DD-APPLICATION-KEY",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.GetStatusCode() != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", got.GetStatusCode(), http.StatusOK)
	}
	if gotAPI != "api-secret" {
		t.Errorf("DD-API-KEY header = %q, want api-secret", gotAPI)
	}
	if gotApp != "app-secret" {
		t.Errorf("DD-APPLICATION-KEY header = %q, want app-secret", gotApp)
	}
}

// TestRequest_DualCarrierMixedHeaderAndQuery confirms the two carriers can use
// different placements (primary header + secondary query) and both are applied,
// with the query-placed secret still redacted from the returned FinalUrl.
func TestRequest_DualCarrierMixedHeaderAndQuery(t *testing.T) {
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()

	var gotHeader, gotParam string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Client-Id")
		gotParam = r.URL.Query().Get("client_secret")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx := newTestContext(t)
	ctx.secretsMap["CLIENT_ID"] = "id-secret"
	ctx.secretsMap["CLIENT_SECRET"] = "cs-secret"

	got, err := nodes.Request(context.Background(), ctx, &gen.HttpRequest{
		Url:              srv.URL,
		AuthType:         "header",
		AuthSecretName:   "CLIENT_ID",
		AuthHeaderName:   "X-Client-Id",
		AuthType_2:       "query",
		AuthSecretName_2: "CLIENT_SECRET",
		AuthParam_2:      "client_secret",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotHeader != "id-secret" {
		t.Errorf("X-Client-Id header = %q, want id-secret", gotHeader)
	}
	if gotParam != "cs-secret" {
		t.Errorf("server saw client_secret = %q, want cs-secret", gotParam)
	}
	if strings.Contains(got.GetFinalUrl(), "cs-secret") {
		t.Errorf("FinalUrl leaked the second secret value: %q", got.GetFinalUrl())
	}
	if !strings.Contains(got.GetFinalUrl(), "client_secret=REDACTED") {
		t.Errorf("FinalUrl = %q, want redacted client_secret param", got.GetFinalUrl())
	}
}

// TestRequest_SecondCarrierErrors confirms the second carrier validates its own
// companion fields and names them with the "_2" suffix in the error, and never
// leaks the second secret value.
func TestRequest_SecondCarrierErrors(t *testing.T) {
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()

	ctx := newTestContext(t)
	ctx.secretsMap["PRIMARY"] = "p"
	ctx.secretsMap["SECOND"] = "should-never-appear-in-any-error"

	cases := []struct {
		name  string
		input *gen.HttpRequest
		want  string
	}{
		{
			name: "missing secret name on carrier 2",
			input: &gen.HttpRequest{
				Url: "https://example.com", AuthType: "bearer", AuthSecretName: "PRIMARY",
				AuthType_2: "header", AuthHeaderName_2: "X-App",
			},
			want: "auth_secret_name_2 is required",
		},
		{
			name: "missing header name on carrier 2",
			input: &gen.HttpRequest{
				Url: "https://example.com", AuthType: "bearer", AuthSecretName: "PRIMARY",
				AuthType_2: "header", AuthSecretName_2: "SECOND",
			},
			want: "auth_header_name_2 is required",
		},
		{
			name: "unknown auth_type_2",
			input: &gen.HttpRequest{
				Url: "https://example.com", AuthType: "bearer", AuthSecretName: "PRIMARY",
				AuthType_2: "basic", AuthSecretName_2: "SECOND",
			},
			want: "unsupported auth_type_2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := nodes.Request(context.Background(), ctx, tc.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.want)
			}
			if strings.Contains(err.Error(), "should-never-appear-in-any-error") {
				t.Errorf("error leaked the second secret value: %q", err.Error())
			}
		})
	}
}

var _ axiom.Context = (*testContext)(nil) // compile-time interface check

// A TRANSPORT-level failure — a malformed URL, a DNS miss, an SSRF refusal, a
// connect error, a timeout — was unconditionally a hard NODE_FAILED, which
// aborts the WHOLE flow ("graph produced no terminal result"). A flow built on
// this node therefore could not express a typed ok:false for a bad or
// unreachable URL: the failure escaped the flow's own error contract, so no
// downstream facade could report it. Repro: fetch-page-markdown with
// {"url":"not-a-url"} or a .invalid host.
//
// typed_errors=true keeps the failure inside the response contract. Default
// false is the original behaviour, byte for byte.

func TestRequest_TypedErrors_BadURLReturnsTypedResponse(t *testing.T) {
	for _, c := range []struct{ name, url, wantCode string }{
		{"not a url", "not-a-url", "INVALID_URL"},
		{"empty", "", "INVALID_URL"},
		{"bad scheme", "ftp://example.com/x", "INVALID_URL"},
		{"no host", "http://", "INVALID_URL"},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, err := nodes.Request(context.Background(), newTestContext(t), &gen.HttpRequest{
				Url: c.url, TypedErrors: true,
			})
			if err != nil {
				t.Fatalf("typed_errors=true must NOT fail the node: %v", err)
			}
			if out.GetErrorCode() != c.wantCode {
				t.Errorf("error_code = %q, want %q", out.GetErrorCode(), c.wantCode)
			}
			if out.GetError() == "" {
				t.Error("error must carry a human-readable reason")
			}
			if out.GetStatusCode() != 0 {
				t.Errorf("status_code = %d, want 0 for a transport failure", out.GetStatusCode())
			}
		})
	}
}

func TestRequest_TypedErrors_UnreachableHost(t *testing.T) {
	out, err := nodes.Request(context.Background(), newTestContext(t), &gen.HttpRequest{
		Url: "https://this-host-does-not-exist.invalid/x", TypedErrors: true, TimeoutMs: 5000,
	})
	if err != nil {
		t.Fatalf("typed_errors=true must NOT fail the node on a DNS miss: %v", err)
	}
	if out.GetErrorCode() != "REQUEST_FAILED" && out.GetErrorCode() != "TIMEOUT" {
		t.Errorf("error_code = %q, want REQUEST_FAILED or TIMEOUT", out.GetErrorCode())
	}
}

func TestRequest_TypedErrors_SSRFRefusalIsTyped(t *testing.T) {
	out, err := nodes.Request(context.Background(), newTestContext(t), &gen.HttpRequest{
		Url: "http://169.254.169.254/latest/meta-data/", TypedErrors: true, TimeoutMs: 5000,
	})
	if err != nil {
		t.Fatalf("typed_errors=true must NOT fail the node on an SSRF refusal: %v", err)
	}
	if out.GetErrorCode() != "BLOCKED_ADDRESS" && out.GetErrorCode() != "REQUEST_FAILED" {
		t.Errorf("error_code = %q, want BLOCKED_ADDRESS", out.GetErrorCode())
	}
	// The refusal must still BE a refusal — never a silent success.
	if out.GetStatusCode() != 0 {
		t.Errorf("a blocked address must not report an HTTP status; got %d", out.GetStatusCode())
	}
}

// Default OFF: every existing flow and connector keeps the original hard-failure
// behaviour exactly.
func TestRequest_TypedErrorsDefaultOffStillFailsHard(t *testing.T) {
	for _, u := range []string{"not-a-url", "", "ftp://example.com/x"} {
		if _, err := nodes.Request(context.Background(), newTestContext(t), &gen.HttpRequest{Url: u}); err == nil {
			t.Errorf("url %q with typed_errors unset must still fail the node (backward compatibility)", u)
		}
	}
}

// A 4xx/5xx is a COMPLETED exchange, not a transport failure — error_code must
// stay empty so `error_code == ""` cannot be confused with "HTTP succeeded".
func TestRequest_TypedErrors_HTTPErrorStatusIsNotATransportError(t *testing.T) {
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"nope"}`))
	}))
	defer srv.Close()

	out, err := nodes.Request(context.Background(), newTestContext(t), &gen.HttpRequest{Url: srv.URL, TypedErrors: true})
	if err != nil {
		t.Fatalf("unexpected node error: %v", err)
	}
	if out.GetErrorCode() != "" {
		t.Errorf("a 404 is a completed exchange; error_code must stay empty, got %q", out.GetErrorCode())
	}
	if out.GetStatusCode() != 404 {
		t.Errorf("status_code = %d, want 404", out.GetStatusCode())
	}
	if len(out.GetBody()) == 0 {
		t.Error("the error body must still be delivered so a facade can parse it")
	}
}
