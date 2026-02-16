package reseed

// Version defines the current release version of the reseed-tools application.
// This version string is used for compatibility checking, update notifications,
// and identifying the software version in server responses and logs.
const Version = "0.3.11"

// HTTP User-Agent constants for I2P protocol compatibility
const (
	// I2pUserAgent mimics wget for I2P router compatibility and standardized request handling.
	// Many I2P implementations expect this specific user agent string for proper reseed operations.
	I2pUserAgent = "Wget/1.11.4"
)

// Random string generation constants for secure token creation
const (
	// letterBytes contains all valid characters for generating random alphabetic strings
	letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" // 52 possibilities
	// letterIdxBits specifies the number of bits needed to represent character indices
	letterIdxBits = 6 // 6 bits to represent 64 possibilities / indexes
	// letterIdxMask provides bit masking for efficient random character selection
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
)
