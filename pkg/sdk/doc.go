// Package sdk is the public, stable contract between Argus and its collectors.
//
// Dependency policy (§4.5 of the specification): pkg/sdk may use the standard
// library plus a tiny set of vetted golang.org/x packages. It must never import
// anything from internal/ or modules/.
//
// Modules never open sockets themselves. They receive Deps.HTTP and Deps.DNS,
// which route through the egress broker where scope, SSRF protection, rate
// limits, caching, circuit breaking, and audit are enforced in one place.
package sdk

import (
	"errors"
	"fmt"
)

// ErrOutOfScope is returned by an Emitter or Deps call when a target or
// request is denied by the scope guard. Callers must fail closed: never
// retry, never fall back to a raw socket.
var ErrOutOfScope = errors.New("sdk: target out of scope")

// ErrCircuitOpen is returned when a module's host circuit breaker is open.
var ErrCircuitOpen = errors.New("sdk: circuit breaker open")

// ErrBudget is returned when a scan-level budget is exhausted.
var ErrBudget = errors.New("sdk: budget exhausted")

// ErrNotSupported is returned by optional platform integrations that are not
// compiled into this binary (offline mode, missing sidecar, air-gapped use).
var ErrNotSupported = errors.New("sdk: not supported")

// ModuleError wraps a collector failure with the module name so the orchestrator
// can attribute it in metrics and audit records without string matching.
type ModuleError struct {
	Module string
	Op     string
	Err    error
}

func (e *ModuleError) Error() string {
	if e.Op == "" {
		return fmt.Sprintf("module %s: %v", e.Module, e.Err)
	}
	return fmt.Sprintf("module %s (%s): %v", e.Module, e.Op, e.Err)
}

func (e *ModuleError) Unwrap() error { return e.Err }

// UnknownEntityError reports a value that cannot be canonicalized as the
// requested entity type. Modules should treat this as a normal skip, not a
// scan-fatal condition.
type UnknownEntityError struct {
	Type  EntityType
	Value string
	Why   string
}

func (e *UnknownEntityError) Error() string {
	return fmt.Sprintf("sdk: cannot canonicalize %q as %s: %s", e.Value, e.Type, e.Why)
}
