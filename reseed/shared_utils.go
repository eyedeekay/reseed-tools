package reseed

// SharedUtilities provides common utility functions used across the reseed package.

import (
	"strings"
)

// AllReseeds contains the comprehensive list of known I2P reseed server URLs.
// These servers provide bootstrap router information for new I2P nodes to join the network.
// The list is used for ping testing and fallback reseed operations when needed.
var AllReseeds = []string{
	"https://banana.incognet.io/",
	"https://i2p.novg.net/",
	"https://i2pseed.creativecowpat.net:8443/",
	"https://reseed-fr.i2pd.xyz/",
	"https://reseed-pl.i2pd.xyz/",
	"https://reseed.diva.exchange/",
	"https://reseed.i2pgit.org/",
	"https://reseed.memcpy.io/",
	"https://reseed.onion.im/",
	"https://reseed2.i2p.net/",
	"https://www2.mk16.de/",
}

// SignerFilenameFromID converts a signer ID into a filesystem-safe filename.
// Replaces '@' symbols with '_at_' to create valid filenames for certificate storage.
// This ensures consistent file naming across different operating systems and filesystems.
func SignerFilenameFromID(signerID string) string {
	return strings.Replace(signerID, "@", "_at_", 1)
}
