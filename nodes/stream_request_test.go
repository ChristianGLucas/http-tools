package nodes_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gen "christiangeorgelucas/http-tools/gen"
	"christiangeorgelucas/http-tools/nodes"
)

func runStreamRequest(t *testing.T, ctx *testContext, req *gen.HttpRequest) []*gen.StreamSseEvent {
	t.Helper()
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()
	in := make(chan *gen.HttpRequest, 1)
	in <- req
	close(in)
	var frames []*gen.StreamSseEvent
	if err := nodes.StreamRequest(context.Background(), ctx, in, func(f *gen.StreamSseEvent) error {
		frames = append(frames, f)
		return nil
	}); err != nil {
		t.Fatalf("StreamRequest returned error: %v", err)
	}
	return frames
}

// An OpenAI-compatible stream: a POST with a JSON body and a bearer key, answered
// with one event per token and a closing [DONE]. Every frame arrives in order,
// the last one is_final, and the server saw the method, body and key.
func TestStreamRequest_PostsBodyAndRelaysEachEvent(t *testing.T) {
	var gotMethod, gotAuth, gotBody, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotAuth, gotAccept = r.Method, r.Header.Get("Authorization"), r.Header.Get("Accept")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		for _, ev := range []string{
			`data: {"choices":[{"delta":{"content":"Hel"}}]}`,
			`data: {"choices":[{"delta":{"content":"lo"}}]}`,
			`data: [DONE]`,
		} {
			_, _ = w.Write([]byte(ev + "\n\n"))
			fl.Flush()
		}
	}))
	defer srv.Close()
	ctx := newTestContext(t)
	ctx.secretsMap["APP_OPENAI_KEY"] = "sk-test"

	frames := runStreamRequest(t, ctx, &gen.HttpRequest{
		Url: srv.URL, Method: "post", Body: []byte(`{"stream":true}`),
		Headers:  map[string]string{"Content-Type": "application/json"},
		AuthType: "bearer", AuthSecretName: "APP_OPENAI_KEY",
	})
	if gotMethod != "POST" || gotBody != `{"stream":true}` || gotAuth != "Bearer sk-test" || gotAccept != "text/event-stream" {
		t.Fatalf("server saw method=%q body=%q auth=%q accept=%q", gotMethod, gotBody, gotAuth, gotAccept)
	}
	want := []string{`{"choices":[{"delta":{"content":"Hel"}}]}`, `{"choices":[{"delta":{"content":"lo"}}]}`, `[DONE]`}
	if len(frames) != len(want) {
		t.Fatalf("got %d frames, want %d: %+v", len(frames), len(want), frames)
	}
	for i, f := range frames {
		if f.GetData() != want[i] || f.GetIndex() != int64(i) || f.GetStatusCode() != 200 || f.GetErrorCode() != "" {
			t.Errorf("frame %d = %+v, want data %q", i, f, want[i])
		}
		if f.GetIsFinal() != (i == len(want)-1) {
			t.Errorf("frame %d is_final = %v", i, f.GetIsFinal())
		}
	}
}

// A provider's refusal is one terminal frame that quotes its own reason.
func TestStreamRequest_ErrorStatusQuotesTheProvidersReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"Incorrect API key provided"}}`))
	}))
	defer srv.Close()
	frames := runStreamRequest(t, newTestContext(t), &gen.HttpRequest{Url: srv.URL, Method: "POST"})
	if len(frames) != 1 || !frames[0].GetIsFinal() || frames[0].GetStatusCode() != 401 ||
		frames[0].GetErrorCode() != "HTTP_ERROR_STATUS" || !strings.Contains(frames[0].GetError(), "Incorrect API key provided") {
		t.Fatalf("frames = %+v", frames)
	}
}

// With typed_errors, an unset secret is an in-band frame naming the problem (a browser
// streaming the answer can say why there is none); without it, the node fails before
// any frame, like the other stream nodes.
func TestStreamRequest_UnsetSecret(t *testing.T) {
	req := &gen.HttpRequest{Url: "https://api.example.com/v1", Method: "POST", AuthType: "bearer", AuthSecretName: "NOPE", TypedErrors: true}
	frames := runStreamRequest(t, newTestContext(t), req)
	if len(frames) != 1 || frames[0].GetErrorCode() != "SECRET_NOT_SET" || !frames[0].GetIsFinal() || !strings.Contains(frames[0].GetError(), `"NOPE"`) {
		t.Fatalf("typed: frames = %+v", frames)
	}

	req.TypedErrors = false
	in := make(chan *gen.HttpRequest, 1)
	in <- req
	close(in)
	emitted := 0
	err := nodes.StreamRequest(context.Background(), newTestContext(t), in, func(*gen.StreamSseEvent) error { emitted++; return nil })
	if err == nil || emitted != 0 {
		t.Fatalf("untyped: err=%v emitted=%d; want a node failure before any frame", err, emitted)
	}
}

func TestStreamRequest_BadMethodAndURLAreTypedPreflight(t *testing.T) {
	for _, tc := range []struct {
		req  *gen.HttpRequest
		code string
	}{
		{&gen.HttpRequest{Url: "ftp://x", TypedErrors: true}, "INVALID_URL"},
		{&gen.HttpRequest{Url: "https://api.example.com", Method: "BREW", TypedErrors: true}, "INVALID_REQUEST"},
	} {
		frames := runStreamRequest(t, newTestContext(t), tc.req)
		if len(frames) != 1 || frames[0].GetErrorCode() != tc.code || !frames[0].GetIsFinal() {
			t.Errorf("%+v: frames = %+v, want one %s frame", tc.req, frames, tc.code)
		}
	}
}

// The SSRF guard holds for the streaming node too: loopback is refused in-band.
func TestStreamRequest_LoopbackIsBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	in := make(chan *gen.HttpRequest, 1)
	in <- &gen.HttpRequest{Url: srv.URL, Method: "POST"}
	close(in)
	var frames []*gen.StreamSseEvent
	if err := nodes.StreamRequest(context.Background(), newTestContext(t), in, func(f *gen.StreamSseEvent) error {
		frames = append(frames, f)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || frames[0].GetErrorCode() != "BLOCKED_ADDRESS" {
		t.Fatalf("frames = %+v", frames)
	}
}
