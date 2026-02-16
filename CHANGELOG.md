2026-02-16
 * app.Version = 0.3.11
 * resolve a bug caused by a misconfigured rate-limiter

2024-06-29
 * app.Version = 0.2.5
 * Add password-protected netDb sync capability

2024-06-25
 * app.Version = 0.2.4
 * Remove dependency on libp2p
 * Use go-i2p to parse RouterInfos prior to inclusion in reseed bundles, exclude less-useful RIs

2023-01-27
 * app.Version = "0.2.32"
 * This changelog has been inadequately updated.
 * At this time, there have been features added.
 * All flags but signer will be filled in with default values or left unused.
 * signer may be configured with an environment variable.
 * A fake homepage is served when a user-agent does not match eepget.
 * Static resources have been embedded in the binary to support the homepage.
 * ACME support has been added.
 * Support for operating an `.onion` service has been added.
 * Support for operating an in-network(`.b32.i2p`) interface to the reseed has been added.
 * Reseed servers can monitor eachother on a rate-limited basis.
 * Support has been added for running as an I2P plugin.
 * Limited support has been added for Debian packages.

2021-12-16
 * app.Version = "0.2.11"
 * include license file in plugin

2021-12-14
 * app.Version = "0.2.10"
 * restart changelog
 * fix websiteURL in plugin.config

2019-04-21
 * app.Version = "0.1.7"
 * enabling TLS 1.3 *only*

2016-12-21
 * deactivating previous random time delta, makes only sense when patching ri too
 * app.Version = "0.1.6"

2016-10-09
 * seed the math random generator with time.Now().UnixNano()
 * added 6h+6h random time delta at su3-age to increase anonymity
 * app.Version = "0.1.5"


2016-05-15
 * README.md updated
 * allowed routerInfos age increased from 96 to 192 hours
 * app.Version = "0.1.4"

2016-03-05
 * app.Version = "0.1.3"
 * CRL creation added

2016-01-31
 * allowed TLS ciphers updated (hardened)
 * TLS certificate generation: RSA 4096 --> ECDSAWithSHA512 384bit secp384r1
 * ECDHE handshake: only CurveP384 + CurveP521, default CurveP256 removed
 * TLS certificate valid: 2y --> 5y
 * throttled.PerDay(4) --> PerHour(4), to enable limited testing
 * su3 RebuildInterval: 24h --> 90h, higher anonymity for the running i2p-router
 * numRi per su3 file: 75 --> 77

2016-01
 * fork from https://i2pgit.org/idk/reseed-tools
