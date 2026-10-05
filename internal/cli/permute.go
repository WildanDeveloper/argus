package cli

import (
	"flag"
	"strings"
)

// permute reorders a command line so that flags precede positional arguments.
//
// Go's flag package stops parsing at the first non-flag argument, so
// `argus scan acme.example -m dns-records` would silently treat "-m dns-records"
// as two more targets. The documented examples put the target first, so the CLI
// accepts flags on either side of it.
//
// A flag that takes a value is detected from the FlagSet rather than guessed, and
// `-flag=value` is recognised so its value is never mistaken for a positional.
// Everything after a bare "--" is left untouched, which is the conventional way to
// pass a literal argument that looks like a flag.
func permute(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			positional = append(positional, arg)
			continue
		}

		flags = append(flags, arg)

		name := strings.TrimLeft(arg, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			// The value is attached, so nothing further is consumed.
			continue
		}
		// A bare "-x" style shorthand: look up by the single rune.
		if len(name) == 1 {
			if f := fs.Lookup(name); f != nil && !isBoolFlag(f) {
				if i+1 < len(args) {
					i++
					flags = append(flags, args[i])
				}
			}
			continue
		}
		if f := fs.Lookup(name); f != nil && !isBoolFlag(f) {
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		}
	}
	return append(flags, positional...)
}

// isBoolFlag reports whether a flag may appear without a value.
//
// A bool flag takes no value, so the argument after it is a separate token. This
// matters for a command like `-q acme.example`, where "acme.example" must stay a
// positional and not be consumed as the value of -q.
func isBoolFlag(f *flag.Flag) bool {
	bf, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && bf.IsBoolFlag()
}

// parse parses args with permutation applied.
func parse(fs *flag.FlagSet, args []string) error {
	return fs.Parse(permute(fs, args))
}
