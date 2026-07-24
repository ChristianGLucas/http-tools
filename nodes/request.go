package nodes

import (
	"context"
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

	client := newGuardedClient(input.GetFollowRedirects())

	ax.Log().Info("http request", "method", method, "url", u.String())
	resp, err := client.Do(req)
	if err != nil {
		// A blocked-address dial surfaces here; keep the message actionable and
		// free of internal detail.
		if isBlockedErr(err) {
			return nil, fmt.Errorf("request to %q refused: resolves to a private or internal address", u.Host)
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
		FinalUrl:   resp.Request.URL.String(),
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
func newGuardedClient(followRedirects bool) *http.Client {
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

// flattenHeaders collapses multi-valued HTTP headers into a single map, joining
// repeated values with ", " (the standard header list separator).
func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}
