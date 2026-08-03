package nodes

import (
	"bytes"
	"context"
	"io"

	"christiangeorgelucas/http-tools/axiom"
	gen "christiangeorgelucas/http-tools/gen"
)

// lineReadBufSize is the size of each underlying Read() call against the
// response body while scanning for line terminators.
const lineReadBufSize = 64 << 10 // 64 KiB

// StreamLines GETs a URL and emits its response body one line at a time,
// read incrementally as it downloads. See StreamLine for the CRLF-handling
// and no-tail-flush contract.
func StreamLines(ctx context.Context, ax axiom.Context, in <-chan *gen.StreamGetRequest, emit func(*gen.StreamLine) error) error {
	for input := range in {
		if err := streamLinesOne(ctx, ax, input, emit); err != nil {
			return err
		}
	}
	return nil
}

// findLineTerminator locates the first "\n" in buf and reports the content
// end (trimming a preceding "\r", so both CRLF and LF are handled) and the
// number of bytes to consume including the terminator itself.
func findLineTerminator(buf []byte) (contentEnd, consumed int, found bool) {
	i := bytes.IndexByte(buf, '\n')
	if i < 0 {
		return 0, 0, false
	}
	end := i
	if i > 0 && buf[i-1] == '\r' {
		end = i - 1
	}
	return end, i + 1, true
}

func streamLinesOne(ctx context.Context, ax axiom.Context, input *gen.StreamGetRequest, emit func(*gen.StreamLine) error) error {
	req, client, cancel, redactParams, err := buildStreamRequest(ctx, ax, input)
	if err != nil {
		return err
	}
	defer cancel()

	ax.Log().Info("stream lines request", "url", redactURL(req.URL, redactParams))
	resp, doErr := client.Do(req)
	if doErr != nil {
		code, msg := classifyTransportError(doErr, req.URL, redactParams)
		return emit(&gen.StreamLine{ErrorCode: code, Error: msg, IsFinal: true})
	}
	defer resp.Body.Close()

	statusCode := int32(resp.StatusCode)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return emit(&gen.StreamLine{
			StatusCode: statusCode,
			ErrorCode:  "HTTP_ERROR_STATUS",
			Error:      httpErrorStatusMessage(resp.StatusCode),
			IsFinal:    true,
		})
	}

	var buf []byte
	readBuf := make([]byte, lineReadBufSize)
	var pending *gen.StreamLine
	lineNumber := int64(0)

	emitCandidate := func(text string) error {
		lineNumber++
		f := &gen.StreamLine{Line: text, LineNumber: lineNumber, StatusCode: statusCode}
		if pending != nil {
			if e := emit(pending); e != nil {
				return e
			}
		}
		pending = f
		return nil
	}

	for {
		n, rerr := resp.Body.Read(readBuf)
		if n > 0 {
			buf = append(buf, readBuf[:n]...)
			for {
				end, consumed, found := findLineTerminator(buf)
				if !found {
					break
				}
				if err := emitCandidate(string(buf[:end])); err != nil {
					return err
				}
				buf = buf[consumed:]
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				// Per StreamLine's contract, a trailing unterminated
				// fragment (whatever remains in buf) is deliberately
				// dropped, not flushed as a final partial line.
				if pending != nil {
					pending.IsFinal = true
					return emit(pending)
				}
				return emit(&gen.StreamLine{StatusCode: statusCode, IsFinal: true})
			}
			if pending != nil {
				if e := emit(pending); e != nil {
					return e
				}
			}
			return emit(&gen.StreamLine{
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
