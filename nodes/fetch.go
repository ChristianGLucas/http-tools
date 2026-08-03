package nodes

import (
	"context"

	"christiangeorgelucas/http-tools/axiom"
	gen "christiangeorgelucas/http-tools/gen"
)

// Fetch is the concrete, direct-use counterpart to the generic Request node:
// same input/output contract, same handler code path (delegates verbatim, so
// there is zero behavior divergence), but placeable directly in a flow graph
// or invoked standalone — no Instance required. See Request's doc comment for
// the full behavior (SSRF-hardened egress, auth carriers, typed_errors, etc).
func Fetch(ctx context.Context, ax axiom.Context, input *gen.HttpRequest) (*gen.HttpResponse, error) {
	return Request(ctx, ax, input)
}
