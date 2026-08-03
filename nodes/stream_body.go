package nodes

import (
	"context"
	"errors"
	"io"

	"christiangeorgelucas/http-tools/axiom"
	gen "christiangeorgelucas/http-tools/gen"
)

// StreamBody GETs a URL and emits its response body as a series of raw byte
// chunks, read incrementally from the response as it downloads — the body is
// never buffered whole in memory. For the start node of a pipeline flow the
// input channel yields exactly one item; see StreamGetRequest for the
// at-least-once/idempotency contract.
func StreamBody(ctx context.Context, ax axiom.Context, in <-chan *gen.StreamGetRequest, emit func(*gen.StreamBodyChunk) error) error {
	for input := range in {
		if err := streamBodyOne(ctx, ax, input, emit); err != nil {
			return err
		}
	}
	return nil
}

func streamBodyOne(ctx context.Context, ax axiom.Context, input *gen.StreamGetRequest, emit func(*gen.StreamBodyChunk) error) error {
	req, client, cancel, redactParams, err := buildStreamRequest(ctx, ax, input)
	if err != nil {
		// Pre-flight/programming error: hard node failure, no frame emitted.
		return err
	}
	defer cancel()

	chunkSize := resolveChunkSize(input.GetChunkSizeBytes())

	ax.Log().Info("stream body request", "url", redactURL(req.URL, redactParams))
	resp, doErr := client.Do(req)
	if doErr != nil {
		code, msg := classifyTransportError(doErr, req.URL, redactParams)
		return emit(&gen.StreamBodyChunk{ErrorCode: code, Error: msg, IsFinal: true})
	}
	defer resp.Body.Close()

	statusCode := int32(resp.StatusCode)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return emit(&gen.StreamBodyChunk{
			StatusCode: statusCode,
			ErrorCode:  "HTTP_ERROR_STATUS",
			Error:      httpErrorStatusMessage(resp.StatusCode),
			IsFinal:    true,
		})
	}

	buf := make([]byte, chunkSize)
	// readChunk fills buf up to chunkSize bytes via a manual loop rather than
	// io.ReadFull: io.ReadFull collapses a genuinely clean end-of-body (the
	// underlying Read returning io.EOF) and a mid-download connection drop
	// (net/http's transfer.go returning io.ErrUnexpectedEOF directly on a
	// Content-Length mismatch) into the SAME io.ErrUnexpectedEOF value
	// whenever any bytes were already read this call — so a black-box
	// io.ReadFull cannot tell "last legitimate partial chunk" from "the
	// connection dropped mid-chunk". Inspecting each raw Read() error
	// preserves that distinction: only a raw io.EOF is a clean stream end.
	readChunk := func() (data []byte, eof bool, err error) {
		n := 0
		for n < len(buf) {
			rn, rerr := resp.Body.Read(buf[n:])
			n += rn
			if rerr != nil {
				if rerr == io.EOF {
					out := make([]byte, n)
					copy(out, buf[:n])
					return out, true, nil
				}
				return nil, false, rerr
			}
		}
		out := make([]byte, n)
		copy(out, buf[:n])
		return out, false, nil
	}

	// One-chunk lookahead: a chunk is only known to be the LAST one once the
	// next read tells us there is nothing more (or that read itself errors).
	var pending *gen.StreamBodyChunk
	offset := int64(0)
	chunksEmitted := 0
	for {
		data, eof, rerr := readChunk()
		if rerr != nil {
			if pending != nil {
				if e := emit(pending); e != nil {
					return e
				}
			}
			return emit(&gen.StreamBodyChunk{
				StatusCode: statusCode,
				ErrorCode:  "BODY_READ_FAILED",
				Error:      "reading response body: " + rerr.Error(),
				IsFinal:    true,
			})
		}
		if len(data) == 0 && eof {
			if pending != nil {
				pending.IsFinal = true
				return emit(pending)
			}
			return emit(&gen.StreamBodyChunk{StatusCode: statusCode, IsFinal: true})
		}

		cur := &gen.StreamBodyChunk{Data: data, ByteOffset: offset, StatusCode: statusCode}
		offset += int64(len(data))
		if pending != nil {
			if e := emit(pending); e != nil {
				return e
			}
			chunksEmitted++
		}
		pending = cur
		if eof {
			pending.IsFinal = true
			if e := emit(pending); e != nil {
				return e
			}
			chunksEmitted++
			ax.Log().Info("stream body complete", "status", resp.StatusCode, "bytes", offset, "chunks", chunksEmitted)
			return nil
		}
		if ctx.Err() != nil {
			return errors.New("stream body: context cancelled")
		}
	}
}
