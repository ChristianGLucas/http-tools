package nodes

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"christiangeorgelucas/http-tools/axiom"
	gen "christiangeorgelucas/http-tools/gen"
)

// maxErrorBodyBytes caps how much of a non-2xx response body StreamRequest
// quotes into its error frame: enough for a provider's own reason ("Incorrect
// API key provided", "model not found"), never a whole page.
const maxErrorBodyBytes = 2 << 10 // 2 KiB

// StreamRequest is the GENERIC streaming HTTP node: any method, a request body
// and up to two auth carriers (the same HttpRequest the Request node takes),
// with a text/event-stream response relayed one frame per dispatched event as
// it arrives. It is what an LLM token stream needs (OpenAI-compatible
// `"stream": true` is a POST with a JSON body), and an Instance binds it like
// Request: the input map builds url/method/body/auth from typed fields, and the
// output map runs once per frame, reading each event's `data`.
//
// Failures are in-band frames (error_code + error, is_final), never a mid-stream
// node failure. With typed_errors=true a pre-flight problem (a bad url, an
// unsupported method, an unset secret) is one too, so a flow streaming to a
// browser can show why there is no answer; without it, pre-flight problems fail
// the node before any frame, like the other stream nodes.
func StreamRequest(ctx context.Context, ax axiom.Context, in <-chan *gen.HttpRequest, emit func(*gen.StreamSseEvent) error) error {
	for input := range in {
		if err := streamRequestOne(ctx, ax, input, emit); err != nil {
			return err
		}
	}
	return nil
}

// preflightError is a problem found before the request is sent.
type preflightError struct {
	code string
	err  error
}

func (e *preflightError) Error() string { return e.err.Error() }

func preflight(code, format string, args ...any) error {
	return &preflightError{code: code, err: fmt.Errorf(format, args...)}
}

func streamRequestOne(ctx context.Context, ax axiom.Context, input *gen.HttpRequest, emit func(*gen.StreamSseEvent) error) error {
	req, client, cancel, redactParams, err := buildStreamHttpRequest(ctx, ax, input)
	if err != nil {
		var pe *preflightError
		if input.GetTypedErrors() && errors.As(err, &pe) {
			return emit(&gen.StreamSseEvent{ErrorCode: pe.code, Error: pe.Error(), IsFinal: true})
		}
		return err
	}
	defer cancel()

	ax.Log().Info("stream request", "method", req.Method, "url", redactURL(req.URL, redactParams))
	resp, doErr := client.Do(req)
	if doErr != nil {
		code, msg := classifyTransportError(doErr, req.URL, redactParams)
		return emit(&gen.StreamSseEvent{ErrorCode: code, Error: msg, IsFinal: true})
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := httpErrorStatusMessage(resp.StatusCode)
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		if text := strings.TrimSpace(strings.ToValidUTF8(string(b), "?")); text != "" {
			msg += ": " + text
		}
		return emit(&gen.StreamSseEvent{
			StatusCode: int32(resp.StatusCode),
			ErrorCode:  "HTTP_ERROR_STATUS",
			Error:      msg,
			IsFinal:    true,
		})
	}
	return relaySse(ctx, resp, emit)
}

// buildStreamHttpRequest resolves an HttpRequest into a ready-to-send request
// with the same URL validation, SSRF-guarded client and auth resolution as the
// Request node. The time budget covers the whole stream (default
// streamDefaultTimeout, under the platform's 5-minute node-stream ceiling).
func buildStreamHttpRequest(ctx context.Context, ax axiom.Context, input *gen.HttpRequest) (req *http.Request, client *http.Client, cancel context.CancelFunc, redactParams []string, err error) {
	u, prob := resolveRequestURL(ax, input)
	if prob != nil {
		// An unset address secret is a pre-flight problem like an unset auth secret (SECRET_NOT_SET).
		return nil, nil, nil, nil, &preflightError{code: prob.code, err: prob.err}
	}
	method := strings.ToUpper(strings.TrimSpace(input.GetMethod()))
	if method == "" {
		method = http.MethodGet
	}
	if !allowedMethods[method] {
		return nil, nil, nil, nil, preflight("INVALID_REQUEST", "unsupported HTTP method %q", method)
	}
	if q := input.GetQuery(); len(q) > 0 {
		vals := u.Query()
		for k, v := range q {
			vals.Set(k, v)
		}
		u.RawQuery = vals.Encode()
	}

	var sensitiveHeaders []string
	var authHeaders []authHeader
	carriers := []struct{ typ, secret, header, param, prefix, suffix string }{
		{input.GetAuthType(), input.GetAuthSecretName(), input.GetAuthHeaderName(), input.GetAuthParam(), input.GetAuthValuePrefix(), ""},
		{input.GetAuthType_2(), input.GetAuthSecretName_2(), input.GetAuthHeaderName_2(), input.GetAuthParam_2(), input.GetAuthValuePrefix_2(), "_2"},
	}
	for _, c := range carriers {
		carrier, aerr := resolveAuthCarrier(ax, u, c.typ, c.secret, c.header, c.param, c.prefix, c.suffix)
		if aerr != nil {
			code := "INVALID_REQUEST"
			if name := strings.TrimSpace(c.secret); name != "" {
				if _, ok := ax.Secrets().Get(name); !ok {
					code = "SECRET_NOT_SET"
				}
			}
			return nil, nil, nil, nil, &preflightError{code: code, err: aerr}
		}
		if carrier.headerName != "" {
			authHeaders = append(authHeaders, authHeader{name: carrier.headerName, value: carrier.headerValue})
			sensitiveHeaders = append(sensitiveHeaders, carrier.headerName)
		}
		if carrier.redactParam != "" {
			redactParams = append(redactParams, carrier.redactParam)
		}
	}

	timeout := streamDefaultTimeout
	if ms := input.GetTimeoutMs(); ms > 0 {
		timeout = time.Duration(ms) * time.Millisecond
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)

	var body io.Reader
	if b := input.GetBody(); len(b) > 0 {
		body = strings.NewReader(string(b))
	}
	req, rerr := http.NewRequestWithContext(reqCtx, method, u.String(), body)
	if rerr != nil {
		cancel()
		return nil, nil, nil, nil, fmt.Errorf("building request: %w", rerr)
	}
	for k, v := range input.GetHeaders() {
		req.Header.Set(k, v)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/event-stream")
	}
	// Auth last, so a caller-supplied header of the same name never masks it.
	for _, h := range authHeaders {
		req.Header.Set(h.name, h.value)
	}
	client = newGuardedClient(input.GetFollowRedirects(), sensitiveHeaders, redactParams)
	return req, client, cancel, redactParams, nil
}
