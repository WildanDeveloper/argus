package egress

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RetryableStatus reports whether an HTTP status warrants a retry.
//
// The set is deliberately narrow. Retrying a 400 or 403 wastes the analyst's
// budget on a request that will never succeed, and retrying a 404 would hammer a
// provider while a module enumerates legitimately absent resources.
func RetryableStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout, // 408
		http.StatusTooManyRequests,     // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout:      // 504
		return true
	}
	return false
}

// RetryAfterFromResponse extracts a Retry-After delay, in either the delta-seconds
// or the HTTP-date form (RFC 9110 §10.2.3).
func RetryAfterFromResponse(resp *http.Response, now time.Time) time.Duration {
	if resp == nil {
		return 0
	}
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// httpStatusError carries a status code so retryable and retryAfter can inspect
// it without the client depending on a response object.
type httpStatusError struct {
	code int
	url  string
}

func (e *httpStatusError) Error() string {
	return "egress: HTTP " + strconv.Itoa(e.code) + " for " + e.url
}

// StatusCode returns the response status.
func (e *httpStatusError) StatusCode() int { return e.code }

// NewStatusError builds an error carrying a status code. Exported for tests and
// for module-local HTTP handling that funnels through the broker.
func NewStatusError(code int, url string) error { return &httpStatusError{code: code, url: url} }

// StatusCode extracts a status code from an error, or 0 when there is none.
func StatusCode(err error) int {
	var se *httpStatusError
	if errors.As(err, &se) {
		return se.code
	}
	return 0
}

// retryAfter returns the delay a server asked for, carried on the error.
func retryAfter(err error) time.Duration {
	type afterer interface{ RetryAfter() time.Duration }
	var a afterer
	if errors.As(err, &a) {
		return a.RetryAfter()
	}
	return 0
}

// statusRetryAfter couples a status code with a Retry-After delay.
type statusRetryAfter struct {
	*httpStatusError
	after time.Duration
}

func (e *statusRetryAfter) RetryAfter() time.Duration { return e.after }
