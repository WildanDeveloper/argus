// Package main blank-imports every first-party module so the compile-time registry
// is populated. Regenerate with `go generate` after adding a module.
package main

import (
	_ "github.com/WildanDeveloper/argus/modules/domain/ctsearch"
	_ "github.com/WildanDeveloper/argus/modules/domain/dnsrecords"
	_ "github.com/WildanDeveloper/argus/modules/domain/passive"
	_ "github.com/WildanDeveloper/argus/modules/domain/rdap"
	_ "github.com/WildanDeveloper/argus/modules/domain/reverse"
	_ "github.com/WildanDeveloper/argus/modules/domain/wayback"
	_ "github.com/WildanDeveloper/argus/modules/domain/whois"
	_ "github.com/WildanDeveloper/argus/modules/media/exif"
	_ "github.com/WildanDeveloper/argus/modules/network/asnlookup"
	_ "github.com/WildanDeveloper/argus/modules/network/ipgeo"
)
