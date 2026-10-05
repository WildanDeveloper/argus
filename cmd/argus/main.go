// Command argus is the Argus CLI.
package main

import (
	"fmt"
	"os"

	"github.com/WildanDeveloper/argus/internal/cli"
)

func main() {
	code, err := cli.Run(os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "argus: "+err.Error())
	}
	os.Exit(code)
}
