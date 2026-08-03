package nodes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"christiangeorgelucas/http-tools/axiom"
	gen "christiangeorgelucas/http-tools/gen"
)

// streamDefaultTimeout is the default overall time budget for a StreamBody /
// StreamLines / StreamSse request: connecting, receiving headers, AND
// reading the full body/event stream to completion. Generous enough to
// carry a full download to completion, while staying safely under the
// platform's hard 5-minute per-node stream ceiling.
const streamDefaultTimeout = 270 * time.Second

const (
	defaultChunkSizeBytes = 1 << 20 // 1 MiB
	minChunkSizeBytes     = 4 << 10 // 4 KiB
	maxChunkSizeBytes     = 4 << 20 // 4 MiB
)

// resolveChunkSize clamps a caller-supplied chunk_size_bytes to the sane
// range [minChunkSizeBytes, maxChunkSizeBytes], defaulting to
// defaultChunkSizeBytes when unset (<=0).
func resolveChunkSize(requested int32) int {
	switch {
	case requested <= 0:
		return defaultChunkSizeBytes
	case requested < minChunkSizeBytes:
		return minChunkSizeBytes
	case requested > maxChunkSizeBytes:
		return maxChunkSizeBytes
	default:
		return int(requested)
	}
}

// buildStreamRequest resolves a StreamGetRequest into a ready-to-send GET
// *http.Request plus the guarded client to send it with, applying the same
// URL validation, SSRF guard, and single-carrier auth resolution as the
// unary Request node. The returned cancel func MUST be deferred by the
// caller to release the request's timeout context.
//
// Returns a Go error only for a PRE-FLIGHT / programming problem (a
// malformed url, an unsupported auth_type, a missing required secret) —
// these fail the node before any frame is emitted, exactly like the unary
// Request node's default behavior for the same class of problem. A
// TRANSPORT failure once the request is issued (DNS, SSRF block, timeout,
// non-2xx status) is never reported this way: a pipeline node cannot
// express a unary error mid-stream, so the caller reports those as an
// in-band terminal error frame instead — see classifyTransportError.
func buildStreamRequest(ctx context.Context, ax axiom.Context, input *gen.StreamGetRequest) (req *http.Request, client *http.Client, cancel context.CancelFunc, redactParams []string, err error) {
	rawURL := strings.TrimSpace(input.GetUrl())
	if rawURL == "" {
		return nil, nil, nil, nil, fmt.Errorf("url is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("invalid url %q: %v", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, nil, nil, nil, fmt.Errorf("unsupported url scheme %q: only http and https are allowed", u.Scheme)
	}
	if u.Host == "" {
		return nil, nil, nil, nil, fmt.Errorf("url %q has no host", rawURL)
	}

	if q := input.GetQuery(); len(q) > 0 {
		vals := u.Query()
		for k, v := range q {
			vals.Set(k, v)
		}
		u.RawQuery = vals.Encode()
	}

	auth, err := resolveAuthCarrier(ax, u,
		input.GetAuthType(), input.GetAuthSecretName(), input.GetAuthHeaderName(),
		input.GetAuthParam(), input.GetAuthValuePrefix(), "")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	var sensitiveHeaders []string
	if auth.headerName != "" {
		sensitiveHeaders = append(sensitiveHeaders, auth.headerName)
	}
	if auth.redactParam != "" {
		redactParams = append(redactParams, auth.redactParam)
	}

	timeout := streamDefaultTimeout
	if ms := input.GetTimeoutMs(); ms > 0 {
		timeout = time.Duration(ms) * time.Millisecond
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)

	req, err = http.NewRequestWithContext(reqCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		cancel()
		return nil, nil, nil, nil, fmt.Errorf("building request: %w", err)
	}
	for k, v := range input.GetHeaders() {
		req.Header.Set(k, v)
	}
	if auth.headerName != "" {
		req.Header.Set(auth.headerName, auth.headerValue)
	}

	client = newGuardedClient(input.GetFollowRedirects(), sensitiveHeaders, redactParams)
	return req, client, cancel, redactParams, nil
}

// classifyTransportError maps a client.Do error to the same machine-readable
// tokens the unary Request node uses for typed_errors, redacting any
// query-placed secret from the message exactly like it does.
func classifyTransportError(err error, u *url.URL, redactParams []string) (code, message string) {
	if isBlockedErr(err) {
		return "BLOCKED_ADDRESS", fmt.Sprintf("request to %q refused: resolves to a private or internal address", u.Host)
	}
	code = "REQUEST_FAILED"
	if errors.Is(err, context.DeadlineExceeded) {
		code = "TIMEOUT"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return code, fmt.Sprintf("request to %s failed: %v", redactURL(u, redactParams), urlErr.Err)
	}
	return code, fmt.Sprintf("request failed: %v", err)
}

// httpErrorStatusMessage renders the human-readable message for a completed
// but non-2xx HTTP exchange.
func httpErrorStatusMessage(statusCode int) string {
	return fmt.Sprintf("unexpected status %d: %s", statusCode, http.StatusText(statusCode))
}
