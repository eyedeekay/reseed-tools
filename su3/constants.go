package su3

// SU3 File format constants
// Moved from: su3.go
const (
	// minVersionLength specifies the minimum required length for version fields in SU3 files.
	// Version fields shorter than this will be zero-padded to meet the requirement.
	minVersionLength = 16

	// SigTypeDSA represents DSA signature algorithm with SHA1 hash.
	// This is the legacy signature type for backward compatibility.
	SigTypeDSA = uint16(0)

	// SigTypeECDSAWithSHA256 represents ECDSA signature algorithm with SHA256 hash.
	// Provides 256-bit security level with efficient elliptic curve cryptography.
	SigTypeECDSAWithSHA256 = uint16(1)

	// SigTypeECDSAWithSHA384 represents ECDSA signature algorithm with SHA384 hash.
	// Provides 384-bit security level for enhanced cryptographic strength.
	SigTypeECDSAWithSHA384 = uint16(2)

	// SigTypeECDSAWithSHA512 represents ECDSA signature algorithm with SHA512 hash.
	// Provides maximum security level with 512-bit hash function.
	SigTypeECDSAWithSHA512 = uint16(3)

	// SigTypeRSAWithSHA256 represents RSA signature algorithm with SHA256 hash.
	// Standard RSA signing with 256-bit hash, commonly used for 2048-bit keys.
	SigTypeRSAWithSHA256 = uint16(4)

	// SigTypeRSAWithSHA384 represents RSA signature algorithm with SHA384 hash.
	// Enhanced RSA signing with 384-bit hash for stronger cryptographic assurance.
	SigTypeRSAWithSHA384 = uint16(5)

	// SigTypeRSAWithSHA512 represents RSA signature algorithm with SHA512 hash.
	// Maximum strength RSA signing with 512-bit hash, default for new SU3 files.
	SigTypeRSAWithSHA512 = uint16(6)

	// Note: Signature type 7 (EdDSA_SHA512_Ed25519) is used for in-network
	// Router Identities and Destinations but is NOT defined for SU3 files.
	// The SU3 specification skips type 7 and uses type 8 for EdDSA.

	// SigTypeEdDSASHA512Ed25519ph represents EdDSA signature with SHA-512 prehash
	// using Ed25519ph (RFC 8032). The data is hashed with SHA-512 before signing.
	// Per I2P SU3 spec, this is type code 0x0008. Signature length is always 64 bytes.
	SigTypeEdDSASHA512Ed25519ph = uint16(8)

	// ContentTypeUnknown indicates SU3 file contains unspecified content type.
	// Used when the content type cannot be determined or is not categorized.
	ContentTypeUnknown = uint8(0)

	// ContentTypeRouter indicates SU3 file contains I2P router information.
	// Typically used for distributing router updates and configurations.
	ContentTypeRouter = uint8(1)

	// ContentTypePlugin indicates SU3 file contains I2P plugin data.
	// Used for distributing plugin packages and extensions to I2P routers.
	ContentTypePlugin = uint8(2)

	// ContentTypeReseed indicates SU3 file contains reseed bundle data.
	// Contains bootstrap router information for new I2P nodes to join the network.
	ContentTypeReseed = uint8(3)

	// ContentTypeNews indicates SU3 file contains news or announcement data.
	// Used for distributing network announcements and informational content.
	ContentTypeNews = uint8(4)

	// ContentTypeBlocklist indicates SU3 file contains blocklist information.
	// Contains lists of blocked or banned router identities for network security.
	ContentTypeBlocklist = uint8(5)

	// FileTypeZIP indicates SU3 file content is compressed in ZIP format.
	// Most common file type for distributing compressed collections of files.
	FileTypeZIP = uint8(0)

	// FileTypeXML indicates SU3 file content is in XML format.
	// Used for structured data and configuration files.
	FileTypeXML = uint8(1)

	// FileTypeHTML indicates SU3 file content is in HTML format.
	// Used for web content and documentation distribution.
	FileTypeHTML = uint8(2)

	// FileTypeXMLGZ indicates SU3 file content is gzip-compressed XML.
	// Combines XML structure with gzip compression for efficient transmission.
	FileTypeXMLGZ = uint8(3)

	// FileTypeTXTGZ indicates SU3 file content is gzip-compressed text.
	// Used for compressed text files and logs.
	FileTypeTXTGZ = uint8(4)

	// FileTypeDMG indicates SU3 file content is in Apple DMG format.
	// Used for macOS application and software distribution.
	FileTypeDMG = uint8(5)

	// FileTypeEXE indicates SU3 file content is a Windows executable.
	// Used for Windows application and software distribution.
	FileTypeEXE = uint8(6)

	// magicBytes defines the magic number identifier for SU3 file format.
	// All valid SU3 files must begin with this exact byte sequence.
	magicBytes = "I2Psu3"
)
