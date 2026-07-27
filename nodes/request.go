package nodes

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"christiangeorgelucas/http-tools/axiom"
	gen "christiangeorgelucas/http-tools/gen"
)

// maxResponseBytes caps how much of a response body the node reads into memory.
// This is a container RAM guard against a rogue endpoint streaming unbounded
// data — NOT a domain payload contract. The platform's transport cap governs
// what actually crosses the wire; a body over that is truncated on the way out
// regardless. It sits far above any realistic payload.
const maxResponseBytes = 32 << 20 // 32 MiB

// defaultTimeout applies when the request specifies no timeout_ms.
const defaultTimeout = 30 * time.Second

// maxRedirects bounds redirect-chasing when follow_redirects is set.
const maxRedirects = 10

// allowedMethods is the set of HTTP methods this node will issue.
var allowedMethods = map[string]bool{
	http.MethodGet: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true, http.MethodHead: true,
	http.MethodOptions: true,
}

// Request performs a single outbound HTTP call and returns the response. It is a
// generic node: an Instance binds the request/response body to a real message so
// a flow author maps typed fields on and off the wire. Egress is SSRF-hardened —
// requests that resolve to loopback, private, link-local, or cloud-metadata
// addresses are refused, and every redirect hop is re-validated.
func Request(ctx context.Context, ax axiom.Context, input *gen.HttpRequest) (*gen.HttpResponse, error) {
	// Validate up front so malformed input fails cleanly rather than deep in the
	// HTTP stack.
	rawURL := strings.TrimSpace(input.GetUrl())
	if rawURL == "" {
		return nil, fmt.Errorf("url is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported url scheme %q: only http and https are allowed", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("url %q has no host", rawURL)
	}

	method := strings.ToUpper(strings.TrimSpace(input.GetMethod()))
	if method == "" {
		method = http.MethodGet
	}
	if !allowedMethods[method] {
		return nil, fmt.Errorf("unsupported HTTP method %q", method)
	}

	// Merge query parameters into the URL's existing query string.
	if q := input.GetQuery(); len(q) > 0 {
		vals := u.Query()
		for k, v := range q {
			vals.Set(k, v)
		}
		u.RawQuery = vals.Encode()
	}

	// Optional API-key auth. The instance config carries only secret NAME(s) and
	// a placement (auth_type/auth_header_name/auth_param) — never a value. The
	// value itself is fetched here, server-side, from the calling tenant's own
	// secret store via ax.Secrets(); it never appears in the manifest, in an
	// Instance's config, or in a CEL adapter. A second, independent carrier
	// (auth_*_2) is supported for APIs that require two credentials on one
	// request (e.g. Datadog's DD-API-KEY + DD-APPLICATION-KEY).
	primaryAuth, err := resolveAuthCarrier(ax, u,
		input.GetAuthType(), input.GetAuthSecretName(), input.GetAuthHeaderName(),
		input.GetAuthParam(), input.GetAuthValuePrefix(), "")
	if err != nil {
		return nil, err
	}
	secondaryAuth, err := resolveAuthCarrier(ax, u,
		input.GetAuthType_2(), input.GetAuthSecretName_2(), input.GetAuthHeaderName_2(),
		input.GetAuthParam_2(), input.GetAuthValuePrefix_2(), "_2")
	if err != nil {
		return nil, err
	}
	var authHeaders []authHeader
	var redactParams []string
	for _, c := range []authCarrier{primaryAuth, secondaryAuth} {
		if c.headerName != "" {
			authHeaders = append(authHeaders, authHeader{name: c.headerName, value: c.headerValue})
		}
		if c.redactParam != "" {
			redactParams = append(redactParams, c.redactParam)
		}
	}

	timeout := defaultTimeout
	if ms := input.GetTimeoutMs(); ms > 0 {
		timeout = time.Duration(ms) * time.Millisecond
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var bodyReader io.Reader
	if b := input.GetBody(); len(b) > 0 {
		bodyReader = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(reqCtx, method, u.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	for k, v := range input.GetHeaders() {
		req.Header.Set(k, v)
	}
	// Set auth headers last so a caller-supplied header of the same name can
	// never mask (or be confused with) a resolved secret.
	var sensitiveHeaders []string
	for _, h := range authHeaders {
		req.Header.Set(h.name, h.value)
		sensitiveHeaders = append(sensitiveHeaders, h.name)
	}

	client := newGuardedClient(input.GetFollowRedirects(), sensitiveHeaders, redactParams)

	// Log only method + URL, and never the value of a query-placed secret —
	// the Authorization/custom-auth header itself is never logged either.
	ax.Log().Info("http request", "method", method, "url", redactURL(u, redactParams))
	resp, err := client.Do(req)
	if err != nil {
		// A blocked-address dial surfaces here; keep the message actionable and
		// free of internal detail.
		if isBlockedErr(err) {
			return nil, fmt.Errorf("request to %q refused: resolves to a private or internal address", u.Host)
		}
		// A transport error is a *url.Error whose message renders the full request
		// URL. url.Error strips only userinfo, NOT the query string — so a
		// query-placed secret (auth_type="query") would otherwise leak into the
		// returned error, and thus into the flow's failure event and logs. Rebuild
		// the message from the redacted URL + the underlying cause instead of
		// %w-ing the raw *url.Error.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return nil, fmt.Errorf("request to %s failed: %v", redactURL(u, redactParams), urlErr.Err)
		}
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	out := &gen.HttpResponse{
		StatusCode: int32(resp.StatusCode),
		Headers:    flattenHeaders(resp.Header),
		Body:       body,
		// Redact any query-placed secret here too: FinalUrl flows out to the
		// caller/flow, so it must never carry a resolved value even though the
		// actual outbound request legitimately did.
		FinalUrl: redactURL(resp.Request.URL, redactParams),
	}
	ax.Log().Info("http response", "status", resp.StatusCode, "bytes", len(body))
	return out, nil
}

// errBlockedAddr marks a dial rejected by the SSRF guard so the caller can map
// it to a clean, non-leaky error message.
var errBlockedAddr = fmt.Errorf("destination address is not permitted")

// blockIP is the dial-time address predicate. It is a package var solely so the
// test suite can substitute a permissive predicate to exercise the happy path
// against a loopback test server — production always uses isBlockedIP, and there
// is no consumer-facing knob to disable the SSRF guard.
var blockIP = isBlockedIP

func isBlockedErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), errBlockedAddr.Error())
}

// newGuardedClient builds an http.Client whose dialer validates the actual
// resolved IP of every connection — including each redirect hop, since every
// hop opens a fresh dial — defeating DNS-rebinding by checking the exact address
// the socket will use rather than re-resolving the hostname.
func newGuardedClient(followRedirects bool, sensitiveHeaders, sensitiveQueryParams []string) *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return errBlockedAddr
			}
			ip := net.ParseIP(host)
			if ip == nil || blockIP(ip) {
				return errBlockedAddr
			}
			return nil
		},
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		Proxy:                 nil, // never route around the dial guard via env proxy
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
	}
	client := &http.Client{Transport: transport}
	if followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to unsupported scheme %q", req.URL.Scheme)
			}
			// Credential-egress guard: Go's http.Client strips Authorization/Cookie
			// on a cross-host redirect, but NOT a custom auth header (e.g. X-API-Key)
			// nor a query-placed secret. Drop the resolved secret whenever the
			// redirect leaves the original host, so a redirect to an
			// attacker-controlled PUBLIC host (which the SSRF IP-guard permits) can't
			// harvest a key the caller only meant for the original host.
			if len(via) > 0 && !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
				for _, h := range sensitiveHeaders {
					req.Header.Del(h)
				}
				if len(sensitiveQueryParams) > 0 {
					q := req.URL.Query()
					changed := false
					for _, p := range sensitiveQueryParams {
						if q.Has(p) {
							q.Del(p)
							changed = true
						}
					}
					if changed {
						req.URL.RawQuery = q.Encode()
					}
				}
			}
			return nil
		}
	} else {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

// isBlockedIP reports whether an IP is off-limits for outbound requests: any
// address that is not a routable public host. Covers loopback, RFC-1918/ULA
// private ranges, link-local (which includes cloud-metadata 169.254.169.254),
// multicast, unspecified, carrier-grade NAT, and 0.0.0.0/8.
func isBlockedIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// 0.0.0.0/8 — "this host on this network".
		if v4[0] == 0 {
			return true
		}
		// 100.64.0.0/10 — carrier-grade NAT.
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
	}
	return false
}

// redactURL renders u as a string with each named query parameter's value
// replaced by a fixed placeholder, so a secret placed via auth_type="query"
// (either carrier) never reaches a log line or the node's own output. Pass a
// nil/empty slice to render the URL unchanged (the common, no-query-auth case).
func redactURL(u *url.URL, redactParams []string) string {
	if len(redactParams) == 0 {
		return u.String()
	}
	redacted := *u
	vals := redacted.Query()
	changed := false
	for _, p := range redactParams {
		if vals.Get(p) != "" {
			vals.Set(p, "REDACTED")
			changed = true
		}
	}
	if changed {
		redacted.RawQuery = vals.Encode()
	}
	return redacted.String()
}

// authCarrier is the resolved effect of one auth configuration: either a header
// to set on the request, or the name of a query parameter that was written onto
// the URL (recorded so its value can be redacted from logs/output and stripped
// on a cross-host redirect). A zero authCarrier means "no auth".
type authCarrier struct {
	headerName  string
	headerValue string
	redactParam string
}

// authHeader is a resolved (name, value) auth header pending on the request.
type authHeader struct {
	name  string
	value string
}

// resolveAuthCarrier validates and resolves ONE optional auth carrier: it
// fetches the named secret server-side via ax.Secrets() and returns how to
// apply it (a header to set, or — for the "query" placement — writes it onto u
// and records the param name to redact). authType "" resolves to a no-op zero
// carrier, so an unconfigured carrier is simply skipped. fieldSuffix ("" for the
// primary carrier, "_2" for the second) only names the offending field in error
// messages. The secret VALUE never leaves this function except as the returned
// header value or as a value written onto u's query.
func resolveAuthCarrier(ax axiom.Context, u *url.URL, authType, secretName, headerName, param, valuePrefix, fieldSuffix string) (authCarrier, error) {
	authType = strings.TrimSpace(authType)
	switch authType {
	case "":
		return authCarrier{}, nil
	case "bearer", "header", "query":
		secretName = strings.TrimSpace(secretName)
		if secretName == "" {
			return authCarrier{}, fmt.Errorf("auth_secret_name%s is required when auth_type%s is %q", fieldSuffix, fieldSuffix, authType)
		}
		secretValue, ok := ax.Secrets().Get(secretName)
		if !ok {
			return authCarrier{}, fmt.Errorf("required secret %q is not configured", secretName)
		}
		switch authType {
		case "bearer":
			return authCarrier{headerName: "Authorization", headerValue: "Bearer " + secretValue}, nil
		case "header":
			headerName = strings.TrimSpace(headerName)
			if headerName == "" {
				return authCarrier{}, fmt.Errorf("auth_header_name%s is required when auth_type%s is \"header\"", fieldSuffix, fieldSuffix)
			}
			// Optional static scheme prefix (e.g. "DeepL-Auth-Key ", "Token ") —
			// the same shape "bearer" uses with "Bearer ". Not trimmed: a
			// trailing space is significant, so it is concatenated verbatim.
			// Empty (default) sends the raw secret value.
			return authCarrier{headerName: headerName, headerValue: valuePrefix + secretValue}, nil
		default: // "query"
			param = strings.TrimSpace(param)
			if param == "" {
				return authCarrier{}, fmt.Errorf("auth_param%s is required when auth_type%s is \"query\"", fieldSuffix, fieldSuffix)
			}
			vals := u.Query()
			vals.Set(param, secretValue)
			u.RawQuery = vals.Encode()
			return authCarrier{redactParam: param}, nil
		}
	default:
		return authCarrier{}, fmt.Errorf("unsupported auth_type%s %q: must be one of \"\", \"bearer\", \"header\", \"query\"", fieldSuffix, authType)
	}
}

// flattenHeaders collapses multi-valued HTTP headers into a single map, joining
// repeated values with ", " (the standard header list separator).
func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}
