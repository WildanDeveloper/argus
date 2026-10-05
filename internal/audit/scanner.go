package audit

import (
	"bufio"
	"io"
)

// scannerBufferSize bounds a single audit line. Detail maps are small, but a
// hostile or buggy module must not be able to force an unbounded allocation.
const scannerBufferSize = 1 << 20 // 1 MiB

func newScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), scannerBufferSize)
	return sc
}
