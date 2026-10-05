package egress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
)

// jarKey is the context key carrying a per-module cookie jar.
type jarKey struct{ module string }

func withJar(ctx context.Context, jar http.CookieJar) context.Context {
	return context.WithValue(ctx, jarKey{}, jar)
}

// JarFromContext returns the cookie jar bound to ctx, if any.
func JarFromContext(ctx context.Context) (http.CookieJar, bool) {
	v := ctx.Value(jarKey{})
	if v == nil {
		return nil, false
	}
	j, ok := v.(http.CookieJar)
	return j, ok
}

// boundedBody is a replayable response body that refuses to hand out more than
// its limit. Every body the broker returns goes through here, so a module that
// forgets to bound its own reads still cannot exhaust memory.
type boundedBody struct {
	r *bytes.Reader
}

func newBoundedBody(b []byte, limit int64) io.ReadCloser {
	if limit > 0 && int64(len(b)) > limit {
		b = b[:limit]
	}
	return &boundedBody{r: bytes.NewReader(b)}
}

func (b *boundedBody) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b *boundedBody) Close() error               { return nil }

// Len reports the remaining unread bytes, for callers that want to know whether
// the body was truncated.
func (b *boundedBody) Len() int { return b.r.Len() }

// ReadAllBounded reads at most limit bytes from r, reporting whether the content
// was cut short. Modules parsing a provider's JSON should use this rather than
// io.ReadAll so one oversized response cannot stall a worker.
func ReadAllBounded(r io.Reader, limit int64) (data []byte, truncated bool, err error) {
	if limit <= 0 {
		limit = DefaultMaxBodyBytes
	}
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > limit {
		return buf[:limit], true, nil
	}
	return buf, false, nil
}

// errBodyTooLarge is returned by callers that need a hard failure rather than
// truncation.
var errBodyTooLarge = errors.New("egress: response body exceeds limit")
