// Package main blank-imports every first-party module so the compile-time registry
// is populated. Regenerate with `go generate` after adding a module.
package main

import (
	_ "github.com/WildanDeveloper/argus/modules/domain/ctsearch"
	_ "github.com/WildanDeveloper/argus/modules/domain/dnsrecords"
	_ "github.com/WildanDeveloper/argus/modules/domain/rdap"
)
