package nodes_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gen "christiangeorgelucas/http-tools/gen"
	"christiangeorgelucas/http-tools/nodes"
)

func runStreamSse(t *testing.T, req *gen.StreamGetRequest) []*gen.StreamSseEvent {
	t.Helper()
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()
	in := make(chan *gen.StreamGetRequest, 1)
	in <- req
	close(in)
	var frames []*gen.StreamSseEvent
	err := nodes.StreamSse(context.Background(), newTestContext(t), in, func(f *gen.StreamSseEvent) error {
		frames = append(frames, f)
		return nil
	})
	if err != nil {
		t.Fatalf("StreamSse returned error: %v", err)
	}
	return frames
}

func sseServer(transcript string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte(transcript))
	}))
}

func TestStreamSse_BasicEvents(t *testing.T) {
	srv := sseServer("id: 1\nevent: greeting\ndata: hello\n\nid: 2\ndata: world\n\n")
	defer srv.Close()

	frames := runStreamSse(t, &gen.StreamGetRequest{Url: srv.URL})
	if len(frames) != 2 {
		t.Fatalf("expected 2 events, got %d: %+v", len(frames), frames)
	}
	if frames[0].GetId() != "1" || frames[0].GetEvent() != "greeting" || frames[0].GetData() != "hello" || frames[0].GetIsFinal() {
		t.Fatalf("unexpected frame 0: %+v", frames[0])
	}
	if frames[1].GetId() != "2" || frames[1].GetEvent() != "message" || frames[1].GetData() != "world" || !frames[1].GetIsFinal() {
		t.Fatalf("unexpected frame 1: %+v", frames[1])
	}
}

func TestStreamSse_CRLFTerminators(t *testing.T) {
	srv := sseServer("data: one\r\n\r\ndata: two\r\n\r\n")
	defer srv.Close()

	frames := runStreamSse(t, &gen.StreamGetRequest{Url: srv.URL})
	if len(frames) != 2 || frames[0].GetData() != "one" || frames[1].GetData() != "two" {
		t.Fatalf("unexpected frames: %+v", frames)
	}
	if !frames[1].GetIsFinal() {
		t.Fatal("expected last frame is_final")
	}
}

func TestStreamSse_MultilineDataJoinedWithNewline(t *testing.T) {
	srv := sseServer("data: line1\ndata: line2\n\n")
	defer srv.Close()

	frames := runStreamSse(t, &gen.StreamGetRequest{Url: srv.URL})
	if len(frames) != 1 || frames[0].GetData() != "line1\nline2" {
		t.Fatalf("unexpected frames: %+v", frames)
	}
}

func TestStreamSse_RetryField(t *testing.T) {
	srv := sseServer("retry: 5000\ndata: x\n\n")
	defer srv.Close()

	frames := runStreamSse(t, &gen.StreamGetRequest{Url: srv.URL})
	if len(frames) != 1 || !frames[0].GetRetrySet() || frames[0].GetRetryMs() != 5000 {
		t.Fatalf("unexpected frames: %+v", frames)
	}
}

func TestStreamSse_CommentsAndUnknownFieldsIgnored(t *testing.T) {
	srv := sseServer(": this is a comment\nunknown-field: whatever\ndata: kept\n\n")
	defer srv.Close()

	frames := runStreamSse(t, &gen.StreamGetRequest{Url: srv.URL})
	if len(frames) != 1 || frames[0].GetData() != "kept" {
		t.Fatalf("unexpected frames: %+v", frames)
	}
}

func TestStreamSse_TrailingEventWithoutBlankLineFlushed(t *testing.T) {
	// No trailing blank line after the last event — per spec deviation
	// documented on StreamSseEvent, this transcript still flushes it.
	srv := sseServer("data: only\n")
	defer srv.Close()

	frames := runStreamSse(t, &gen.StreamGetRequest{Url: srv.URL})
	if len(frames) != 1 || frames[0].GetData() != "only" || !frames[0].GetIsFinal() {
		t.Fatalf("unexpected frames: %+v", frames)
	}
}

func TestStreamSse_EmptyBodyZeroEvents(t *testing.T) {
	srv := sseServer("")
	defer srv.Close()

	frames := runStreamSse(t, &gen.StreamGetRequest{Url: srv.URL})
	if len(frames) != 1 || !frames[0].GetIsFinal() || frames[0].GetData() != "" {
		t.Fatalf("expected 1 terminal empty frame, got %+v", frames)
	}
}

func TestStreamSse_404IsErrorFrame(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	frames := runStreamSse(t, &gen.StreamGetRequest{Url: srv.URL})
	if len(frames) != 1 || frames[0].GetErrorCode() != "HTTP_ERROR_STATUS" || frames[0].GetStatusCode() != 404 {
		t.Fatalf("unexpected frames: %+v", frames)
	}
}

func TestStreamSse_CRLFSplitAcrossReadBoundary(t *testing.T) {
	// The "\r" of a "\r\n" terminator arrives in one Read() call, its paired
	// "\n" in the NEXT — the ambiguous case sseLineSplitter's heldCR state
	// exists for. A flush + delay forces the server to deliver these as two
	// distinct TCP reads rather than one coalesced read.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: first\r"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(50 * time.Millisecond)
		w.Write([]byte("\n\r\ndata: second\r\n\r\n"))
	}))
	defer srv.Close()

	frames := runStreamSse(t, &gen.StreamGetRequest{Url: srv.URL})
	if len(frames) != 2 {
		t.Fatalf("expected 2 events, got %d: %+v", len(frames), frames)
	}
	if frames[0].GetData() != "first" || frames[1].GetData() != "second" {
		t.Fatalf("expected clean split data with no stray CR, got %q and %q", frames[0].GetData(), frames[1].GetData())
	}
	if !frames[1].GetIsFinal() {
		t.Fatal("expected last frame final")
	}
}

func TestStreamSse_ManyEventsIdPersistsAcrossEvents(t *testing.T) {
	var transcript string
	const n = 500
	for i := 0; i < n; i++ {
		transcript += "data: tick\n\n"
	}
	srv := sseServer("id: fixed-id\n" + transcript)
	defer srv.Close()

	frames := runStreamSse(t, &gen.StreamGetRequest{Url: srv.URL})
	if len(frames) != n {
		t.Fatalf("expected %d events, got %d", n, len(frames))
	}
	for i, f := range frames {
		if f.GetId() != "fixed-id" {
			t.Fatalf("event %d: id=%q, want persisted id", i, f.GetId())
		}
		if f.GetIndex() != int64(i) {
			t.Fatalf("event %d: index=%d", i, f.GetIndex())
		}
	}
	if !frames[n-1].GetIsFinal() {
		t.Fatal("expected last event final")
	}
}
