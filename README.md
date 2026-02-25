I2P Reseed Tools
==================

![Reseed Tools Poster](content/images/reseed.png)

This tool provides a secure and efficient reseed server for the I2P network.
There are several utility commands to create, sign, and validate SU3 files.
Please note that this requires at least Go version 1.24, and uses Go Modules.

Standard reseeds are distributed with the I2P packages. To get your reseed
included, apply on [i2pforum.i2p](http://i2pforum.i2p).

## Dependencies

`go`, `git`, and optionally `make` are required to build the project.
Precompiled binaries for most platforms are available at the github mirror
https://github.com/go-i2p/reseed-tools.

In order to install the build-dependencies on Ubuntu or Debian, you may use:

```sh
sudo apt-get install golang-go git make
```

## Installation

Reseed-tools can be run as a user, as a freestanding service, or be installed
as an I2P Plugin. It will attempt to configure itself automatically. You should
make sure to set the `--signer` flag or the `RESEED_EMAIL` environment variable
to configure your signing keys/contact info.

### Installation(From Source)

```
git clone https://i2pgit.org/go-i2p/reseed-tools
cd reseed-tools
make build
# Optionally, if you want to install to /usr/bin/reseed-tools
sudo make install
```

## Logging Configuration

The reseed-tools uses structured logging with configurable verbosity levels via the `github.com/go-i2p/logger` package. Logging is controlled through environment variables:

### Environment Variables

- **`DEBUG_I2P`**: Controls logging verbosity levels
  - `debug` - Enable debug level logging (most verbose)
  - `warn` - Enable warning level logging
  - `error` - Enable error level logging only
  - Not set - Logging disabled (default)

- **`WARNFAIL_I2P`**: Enable fast-fail mode for testing
  - `true` - Warnings and errors become fatal for robust testing
  - Not set - Normal operation (default)

### Examples

```bash
# Enable debug logging
export DEBUG_I2P=debug
./reseed-tools reseed --signer=you@mail.i2p --netdb=/home/i2p/.i2p/netDb

# Enable warning/error logging with fast-fail for testing
export DEBUG_I2P=warn
export WARNFAIL_I2P=true
./reseed-tools reseed --signer=you@mail.i2p --netdb=/home/i2p/.i2p/netDb

# Production mode (no logging)
./reseed-tools reseed --signer=you@mail.i2p --netdb=/home/i2p/.i2p/netDb
```

The structured logging provides rich context for debugging I2P network operations, server startup, and file processing while maintaining zero performance impact in production when logging is disabled.

## Usage

#### Debian/Ubuntu note:

It is possible to create a `.deb` package using [these instructions](docs/DEBIAN.md).

Debian users who are running I2P as a system service must also run the 
`reseed-tools` as the same user. This is so that the reseed-tools can access
the I2P service's netDb directory. On Debian and Ubuntu, that user is `i2psvc`
and the netDb directory is: `/var/lib/i2p/i2p-config/netDb`.

## Example Commands:

### Without a webserver, standalone with TLS support

If this is your first time running a reseed server (ie. you don't have any existing keys),
you can simply run the command and follow the prompts to create the appropriate keys, crl and certificates.
Afterwards an HTTPS reseed server will start on the default port and generate 6 files in your current directory
(a TLS key, certificate and crl, and a su3-file signing key, certificate and crl).

```
reseed-tools reseed --signer=you@mail.i2p --netdb=/home/i2p/.i2p/netDb --tlsHost=your-domain.tld
```

### Locally behind a webserver (reverse proxy setup), preferred:

If you are using a reverse proxy server it may provide the TLS certificate instead.

```
reseed-tools reseed --signer=you@mail.i2p --netdb=/home/i2p/.i2p/netDb --port=8443 --ip=127.0.0.1 --trustProxy
```

- **Usage** [More examples can be found here.](docs/EXAMPLES.md)
- **Docker** [Docker examples can be found here](docs/DOCKER.md)
