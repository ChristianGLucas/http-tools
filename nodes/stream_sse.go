package nodes

import (
	"context"
	"io"
	"strconv"
	"strings"

	"christiangeorgelucas/http-tools/axiom"
	gen "christiangeorgelucas/http-tools/gen"
)

// sseReadBufSize is the size of each underlying Read() call against the
// response body while scanning for SSE lines.
const sseReadBufSize = 8 << 10 // 8 KiB — small, since SSE events are typically tiny (LLM tokens).

// sseLineSplitter incrementally extracts lines from a live byte stream,
// treating "\r\n", a lone "\r", or a lone "\n" as ONE line terminator per
// the WHATWG event-stream spec, and correctly handling a "\r" that lands at
// the very end of one Read() with its paired "\n" (if any) arriving in the
// next — never splitting that pair into two lines.
type sseLineSplitter struct {
	buf    []byte
	heldCR bool
}

func (s *sseLineSplitter) feed(chunk []byte) []string {
	b := chunk
	if s.heldCR {
		s.heldCR = false
		if len(b) > 0 && b[0] == '\n' {
			b = b[1:]
		}
	}
	s.buf = append(s.buf, b...)

	var lines []string
	for {
		n := len(s.buf)
		if n == 0 {
			break
		}
		idx := -1
		termLen := 0
		ambiguous := false
		for i := 0; i < n; i++ {
			c := s.buf[i]
			if c == '\n' {
				idx, termLen = i, 1
				break
			}
			if c == '\r' {
				if i+1 < n {
					if s.buf[i+1] == '\n' {
						idx, termLen = i, 2
					} else {
						idx, termLen = i, 1
					}
				} else {
					ambiguous = true
				}
				break
			}
		}
		if ambiguous {
			lines = append(lines, string(s.buf[:n-1]))
			s.buf = nil
			s.heldCR = true
			break
		}
		if idx < 0 {
			break
		}
		lines = append(lines, string(s.buf[:idx]))
		s.buf = s.buf[idx+termLen:]
	}
	return lines
}

// final flushes whatever remains in the buffer as the last line (matching
// the guaranteed trailing segment strings.Split leaves after the final
// terminator, even if empty) — called exactly once when the body is
// exhausted.
func (s *sseLineSplitter) final() string {
	line := string(s.buf)
	s.buf = nil
	return line
}

// StreamSse GETs a text/event-stream URL and emits one frame per dispatched
// SSE event, parsed per the WHATWG "event stream" parsing algorithm as bytes
// arrive live. Runs until the server closes the connection or the platform's
// 5-minute node-stream ceiling, whichever is first.
func StreamSse(ctx context.Context, ax axiom.Context, in <-chan *gen.StreamGetRequest, emit func(*gen.StreamSseEvent) error) error {
	for input := range in {
		if err := streamSseOne(ctx, ax, input, emit); err != nil {
			return err
		}
	}
	return nil
}

// parseAsciiDigits reports whether s consists of one or more ASCII digits
// (the SSE spec's condition for a valid "retry:" reconnection-time value)
// and, if so, its parsed value.
func parseAsciiDigits(s string) (int32, bool) {
	if s == "" {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return int32(n), true
}

func streamSseOne(ctx context.Context, ax axiom.Context, input *gen.StreamGetRequest, emit func(*gen.StreamSseEvent) error) error {
	req, client, cancel, redactParams, err := buildStreamRequest(ctx, ax, input)
	if err != nil {
		return err
	}
	defer cancel()

	ax.Log().Info("stream sse request", "url", redactURL(req.URL, redactParams))
	resp, doErr := client.Do(req)
	if doErr != nil {
		code, msg := classifyTransportError(doErr, req.URL, redactParams)
		return emit(&gen.StreamSseEvent{ErrorCode: code, Error: msg, IsFinal: true})
	}
	defer resp.Body.Close()

	statusCode := int32(resp.StatusCode)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return emit(&gen.StreamSseEvent{
			StatusCode: statusCode,
			ErrorCode:  "HTTP_ERROR_STATUS",
			Error:      httpErrorStatusMessage(resp.StatusCode),
			IsFinal:    true,
		})
	}

	var (
		splitter     sseLineSplitter
		dataBuf      strings.Builder
		eventTypeBuf string
		idBuf        string
		retryBuf     int32
		retrySet     bool
		pending      *gen.StreamSseEvent
		idx          int64
	)

	dispatch := func() error {
		if dataBuf.Len() == 0 {
			eventTypeBuf = ""
			return nil
		}
		data := strings.TrimSuffix(dataBuf.String(), "\n")
		evType := eventTypeBuf
		if evType == "" {
			evType = "message"
		}
		f := &gen.StreamSseEvent{
			Index: idx, Id: idBuf, Event: evType, Data: data,
			RetryMs: retryBuf, RetrySet: retrySet, StatusCode: statusCode,
		}
		idx++
		dataBuf.Reset()
		eventTypeBuf = ""
		if pending != nil {
			if e := emit(pending); e != nil {
				return e
			}
		}
		pending = f
		return nil
	}

	processLine := func(line string) error {
		if line == "" {
			return dispatch()
		}
		if strings.HasPrefix(line, ":") {
			return nil
		}
		field, value, hasColon := strings.Cut(line, ":")
		if hasColon {
			value = strings.TrimPrefix(value, " ")
		}
		switch field {
		case "event":
			eventTypeBuf = value
		case "data":
			dataBuf.WriteString(value)
			dataBuf.WriteByte('\n')
		case "id":
			if !strings.ContainsRune(value, 0) {
				idBuf = value
			}
		case "retry":
			if n, ok := parseAsciiDigits(value); ok {
				retryBuf = n
				retrySet = true
			}
		}
		return nil
	}

	readBuf := make([]byte, sseReadBufSize)
	for {
		n, rerr := resp.Body.Read(readBuf)
		if n > 0 {
			for _, line := range splitter.feed(readBuf[:n]) {
				if err := processLine(line); err != nil {
					return err
				}
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				if err := processLine(splitter.final()); err != nil {
					return err
				}
				if err := dispatch(); err != nil {
					return err
				}
				if pending == nil {
					return emit(&gen.StreamSseEvent{StatusCode: statusCode, IsFinal: true})
				}
				pending.IsFinal = true
				return emit(pending)
			}
			if pending != nil {
				if e := emit(pending); e != nil {
					return e
				}
			}
			return emit(&gen.StreamSseEvent{
				StatusCode: statusCode,
				ErrorCode:  "BODY_READ_FAILED",
				Error:      "reading response body: " + rerr.Error(),
				IsFinal:    true,
			})
		}
		if ctx.Err() != nil {
			if pending != nil {
				_ = emit(pending)
			}
			return ctx.Err()
		}
	}
}
