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

// runStreamBody drives StreamBody with a single-item input channel (as the
// platform does for a pipeline flow's start node) against a real loopback
// httptest.Server (allowed past the SSRF guard for this call only) and
// collects every emitted frame in order.
func runStreamBody(t *testing.T, req *gen.StreamGetRequest) []*gen.StreamBodyChunk {
	t.Helper()
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()
	in := make(chan *gen.StreamGetRequest, 1)
	in <- req
	close(in)
	var frames []*gen.StreamBodyChunk
	err := nodes.StreamBody(context.Background(), newTestContext(t), in, func(f *gen.StreamBodyChunk) error {
		frames = append(frames, f)
		return nil
	})
	if err != nil {
		t.Fatalf("StreamBody returned error: %v", err)
	}
	return frames
}

func TestStreamBody_SmallBodyOneChunk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	}))
	defer srv.Close()

	frames := runStreamBody(t, &gen.StreamGetRequest{Url: srv.URL})
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d: %+v", len(frames), frames)
	}
	f := frames[0]
	if string(f.GetData()) != "hello world" || !f.GetIsFinal() || f.GetByteOffset() != 0 || f.GetStatusCode() != 200 {
		t.Fatalf("unexpected frame: %+v", f)
	}
}

func TestStreamBody_MultiChunkOrderAndOffsets(t *testing.T) {
	body := make([]byte, 0, 30000)
	for i := 0; i < 30000; i++ {
		body = append(body, byte('a'+i%26))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	frames := runStreamBody(t, &gen.StreamGetRequest{Url: srv.URL, ChunkSizeBytes: 4096})
	if len(frames) == 0 {
		t.Fatal("expected at least one frame")
	}
	var reassembled []byte
	for i, f := range frames {
		isLast := i == len(frames)-1
		if f.GetIsFinal() != isLast {
			t.Fatalf("frame %d: is_final=%v, want %v (last=%d)", i, f.GetIsFinal(), isLast, len(frames)-1)
		}
		if f.GetByteOffset() != int64(len(reassembled)) {
			t.Fatalf("frame %d: byte_offset=%d, want %d", i, f.GetByteOffset(), len(reassembled))
		}
		reassembled = append(reassembled, f.GetData()...)
	}
	if string(reassembled) != string(body) {
		t.Fatalf("reassembled body mismatch: got %d bytes, want %d bytes", len(reassembled), len(body))
	}
	// Confirm real chunking happened (not one giant frame).
	if len(frames) < 5 {
		t.Fatalf("expected multiple chunks with a 4096-byte chunk size over a 30000-byte body, got %d", len(frames))
	}
}

func TestStreamBody_ChunkSizeClampedToRange(t *testing.T) {
	body := make([]byte, 10000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	// A tiny requested chunk size clamps up to minChunkSizeBytes (4 KiB), so
	// a 10000-byte body still fits in 3 chunks (4096+4096+1808), not 10000.
	frames := runStreamBody(t, &gen.StreamGetRequest{Url: srv.URL, ChunkSizeBytes: 1})
	if len(frames) > 5 {
		t.Fatalf("chunk size 1 should have clamped up to 4KiB, got %d frames for a 10000-byte body", len(frames))
	}
}

func TestStreamBody_EmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	frames := runStreamBody(t, &gen.StreamGetRequest{Url: srv.URL})
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame for empty body, got %d", len(frames))
	}
	if len(frames[0].GetData()) != 0 || !frames[0].GetIsFinal() || frames[0].GetErrorCode() != "" {
		t.Fatalf("unexpected empty-body frame: %+v", frames[0])
	}
}

func TestStreamBody_404IsErrorFrameNotDataStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found body"))
	}))
	defer srv.Close()

	frames := runStreamBody(t, &gen.StreamGetRequest{Url: srv.URL})
	if len(frames) != 1 {
		t.Fatalf("expected exactly 1 error frame for a 404, got %d: %+v", len(frames), frames)
	}
	f := frames[0]
	if f.GetErrorCode() != "HTTP_ERROR_STATUS" || f.GetStatusCode() != 404 || !f.GetIsFinal() || len(f.GetData()) != 0 {
		t.Fatalf("unexpected 404 frame: %+v", f)
	}
}

func TestStreamBody_InvalidURLFailsHard(t *testing.T) {
	in := make(chan *gen.StreamGetRequest, 1)
	in <- &gen.StreamGetRequest{Url: "not-a-url"}
	close(in)
	err := nodes.StreamBody(context.Background(), newTestContext(t), in, func(f *gen.StreamBodyChunk) error {
		t.Fatalf("expected no frames emitted for a pre-flight failure, got %+v", f)
		return nil
	})
	if err == nil {
		t.Fatal("expected a hard node error for an invalid url")
	}
}

func TestStreamBody_BlockedAddressIsErrorFrame(t *testing.T) {
	// Deliberately does NOT use runStreamBody: this test exercises the real
	// production SSRF guard (loopback refused), not the test override.
	in := make(chan *gen.StreamGetRequest, 1)
	in <- &gen.StreamGetRequest{Url: "http://127.0.0.1:1/x"}
	close(in)
	var frames []*gen.StreamBodyChunk
	err := nodes.StreamBody(context.Background(), newTestContext(t), in, func(f *gen.StreamBodyChunk) error {
		frames = append(frames, f)
		return nil
	})
	if err != nil {
		t.Fatalf("StreamBody returned error: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 error frame, got %d", len(frames))
	}
	if frames[0].GetErrorCode() != "BLOCKED_ADDRESS" || !frames[0].GetIsFinal() {
		t.Fatalf("unexpected frame: %+v", frames[0])
	}
}

func TestStreamBody_MidDownloadDropIsErrorFrame(t *testing.T) {
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000") // promise far more than we send
		w.WriteHeader(200)
		w.Write(make([]byte, 8192)) // one chunk's worth, then abort
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("ResponseWriter does not support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		conn.Close() // simulate a dropped connection mid-download
	}))
	defer srv.Close()

	in := make(chan *gen.StreamGetRequest, 1)
	in <- &gen.StreamGetRequest{Url: srv.URL, ChunkSizeBytes: 4096}
	close(in)
	var frames []*gen.StreamBodyChunk
	err := nodes.StreamBody(context.Background(), newTestContext(t), in, func(f *gen.StreamBodyChunk) error {
		frames = append(frames, f)
		return nil
	})
	if err != nil {
		t.Fatalf("StreamBody returned error: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("expected at least the terminal error frame")
	}
	last := frames[len(frames)-1]
	if last.GetErrorCode() != "BODY_READ_FAILED" || !last.GetIsFinal() {
		t.Fatalf("expected a terminal BODY_READ_FAILED frame, got %+v", last)
	}
	// Any data frames emitted before the drop must NOT be marked final.
	for _, f := range frames[:len(frames)-1] {
		if f.GetIsFinal() {
			t.Fatalf("a pre-drop data frame was incorrectly marked final: %+v", f)
		}
	}
}

func TestStreamBody_MidChunkDropDoesNotLoseAlreadyReadBytes(t *testing.T) {
	// Regression test: the drop happens NOT at a chunk-size boundary (100
	// bytes in, well short of the 4096-byte chunk) — readChunk's manual
	// Read loop must still surface those 100 genuinely-downloaded bytes as
	// a data frame instead of silently discarding them.
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
		w.WriteHeader(200)
		w.Write(make([]byte, 100))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Force the 100 bytes to reach the client as a distinct, earlier
		// Read() call rather than being coalesced with the connection
		// close into one Read() that returns data+error together (which
		// would trivially "work" regardless of whether the fix is
		// present, defeating the point of this regression test).
		time.Sleep(50 * time.Millisecond)
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("ResponseWriter does not support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		conn.Close()
	}))
	defer srv.Close()

	in := make(chan *gen.StreamGetRequest, 1)
	in <- &gen.StreamGetRequest{Url: srv.URL, ChunkSizeBytes: 4096}
	close(in)
	var frames []*gen.StreamBodyChunk
	err := nodes.StreamBody(context.Background(), newTestContext(t), in, func(f *gen.StreamBodyChunk) error {
		frames = append(frames, f)
		return nil
	})
	if err != nil {
		t.Fatalf("StreamBody returned error: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames (the 100 genuinely-read bytes, then the terminal error), got %d: %+v", len(frames), frames)
	}
	if len(frames[0].GetData()) != 100 || frames[0].GetIsFinal() {
		t.Fatalf("expected the first frame to carry the 100 bytes actually read and NOT be final, got %+v", frames[0])
	}
	if frames[1].GetErrorCode() != "BODY_READ_FAILED" || !frames[1].GetIsFinal() || len(frames[1].GetData()) != 0 {
		t.Fatalf("expected a terminal BODY_READ_FAILED frame, got %+v", frames[1])
	}
}

func TestStreamBody_MultiFrameInputChannel(t *testing.T) {
	// StreamBody is itself a START node in every real flow (one request per
	// execution), but the handler signature allows the platform to feed
	// several input messages in one invocation — verify each is handled
	// independently and in order, exactly like the unary node would handle
	// repeated calls.
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("x"))
	}))
	defer srv.Close()

	in := make(chan *gen.StreamGetRequest, 2)
	in <- &gen.StreamGetRequest{Url: srv.URL}
	in <- &gen.StreamGetRequest{Url: srv.URL}
	close(in)
	var frames []*gen.StreamBodyChunk
	err := nodes.StreamBody(context.Background(), newTestContext(t), in, func(f *gen.StreamBodyChunk) error {
		frames = append(frames, f)
		return nil
	})
	if err != nil {
		t.Fatalf("StreamBody returned error: %v", err)
	}
	if len(frames) != 2 || !frames[0].GetIsFinal() || !frames[1].GetIsFinal() {
		t.Fatalf("expected 2 independently-final frames, got %+v", frames)
	}
}
