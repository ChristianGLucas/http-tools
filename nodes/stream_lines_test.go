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

func runStreamLines(t *testing.T, req *gen.StreamGetRequest) []*gen.StreamLine {
	t.Helper()
	restore := nodes.SetBlockIPForTest(func(net.IP) bool { return false })
	defer restore()
	in := make(chan *gen.StreamGetRequest, 1)
	in <- req
	close(in)
	var frames []*gen.StreamLine
	err := nodes.StreamLines(context.Background(), newTestContext(t), in, func(f *gen.StreamLine) error {
		frames = append(frames, f)
		return nil
	})
	if err != nil {
		t.Fatalf("StreamLines returned error: %v", err)
	}
	return frames
}

func TestStreamLines_LFAndCRLF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("one\ntwo\r\nthree\n"))
	}))
	defer srv.Close()

	frames := runStreamLines(t, &gen.StreamGetRequest{Url: srv.URL})
	want := []string{"one", "two", "three"}
	if len(frames) != len(want) {
		t.Fatalf("expected %d lines, got %d: %+v", len(want), len(frames), frames)
	}
	for i, f := range frames {
		if f.GetLine() != want[i] {
			t.Errorf("line %d: got %q, want %q", i, f.GetLine(), want[i])
		}
		if f.GetLineNumber() != int64(i+1) {
			t.Errorf("line %d: line_number=%d, want %d", i, f.GetLineNumber(), i+1)
		}
		if f.GetIsFinal() != (i == len(frames)-1) {
			t.Errorf("line %d: is_final=%v", i, f.GetIsFinal())
		}
	}
}

func TestStreamLines_NoTrailingNewlineDropsLastLine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("one\ntwo\nincomplete-tail-no-newline"))
	}))
	defer srv.Close()

	frames := runStreamLines(t, &gen.StreamGetRequest{Url: srv.URL})
	// Per StreamLine's documented contract: no tail flush, so the
	// unterminated final fragment is dropped.
	want := []string{"one", "two"}
	if len(frames) != len(want) {
		t.Fatalf("expected %d lines (tail dropped), got %d: %+v", len(want), len(frames), frames)
	}
	for i, f := range frames {
		if f.GetLine() != want[i] {
			t.Errorf("line %d: got %q, want %q", i, f.GetLine(), want[i])
		}
	}
	if !frames[len(frames)-1].GetIsFinal() {
		t.Fatal("expected last frame is_final=true")
	}
}

func TestStreamLines_NoNewlineAtAllYieldsNoLines(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("no newline anywhere in this body"))
	}))
	defer srv.Close()

	frames := runStreamLines(t, &gen.StreamGetRequest{Url: srv.URL})
	if len(frames) != 1 {
		t.Fatalf("expected 1 terminal frame with zero lines, got %d: %+v", len(frames), frames)
	}
	if frames[0].GetLine() != "" || frames[0].GetLineNumber() != 0 || !frames[0].GetIsFinal() {
		t.Fatalf("unexpected frame: %+v", frames[0])
	}
}

func TestStreamLines_EmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	frames := runStreamLines(t, &gen.StreamGetRequest{Url: srv.URL})
	if len(frames) != 1 || !frames[0].GetIsFinal() {
		t.Fatalf("expected 1 final empty frame, got %+v", frames)
	}
}

func TestStreamLines_404IsErrorFrame(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	frames := runStreamLines(t, &gen.StreamGetRequest{Url: srv.URL})
	if len(frames) != 1 {
		t.Fatalf("expected 1 error frame, got %d", len(frames))
	}
	if frames[0].GetErrorCode() != "HTTP_ERROR_STATUS" || frames[0].GetStatusCode() != 404 {
		t.Fatalf("unexpected frame: %+v", frames[0])
	}
}

func TestStreamLines_ManyLinesOrderPreserved(t *testing.T) {
	var body []byte
	const n = 2000
	for i := 0; i < n; i++ {
		body = append(body, []byte("line-content-here\n")...)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	frames := runStreamLines(t, &gen.StreamGetRequest{Url: srv.URL})
	if len(frames) != n {
		t.Fatalf("expected %d lines, got %d", n, len(frames))
	}
	for i, f := range frames {
		if f.GetLineNumber() != int64(i+1) {
			t.Fatalf("line %d out of order: line_number=%d", i, f.GetLineNumber())
		}
	}
	if !frames[n-1].GetIsFinal() {
		t.Fatal("expected last frame is_final=true")
	}
	for i := 0; i < n-1; i++ {
		if frames[i].GetIsFinal() {
			t.Fatalf("frame %d unexpectedly final", i)
		}
	}
}
