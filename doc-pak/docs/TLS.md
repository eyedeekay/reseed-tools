TLS Configuration for your Reseed Server
========================================

By default, `reseed-tools` will generate self-signed certificates for your reseed service.
This is so that it can use TLS by default, and so that it can offer self-signed certificates when operating in `.onion` mode.
It is also possible to configure `reseed-tools` without TLS certificates,
or to configure it to use ACME in order to automtically obtain a certificate from Let's Encrypt.

I2P does not rely on TLS Certificate Authorities to authenticate reseed servers.
Instead, the certificates are effectively "Pinned" in the software, after manual review by the I2P developers and the community.
It is acceptable to use self-signed certificates in this fashion because they are not summarily trusted.
A self-signed certificate which is not configured in the I2P software will not work when serving a reseed to an I2P router.

Disable TLS
-----------

If you do this, it is highly recommended that you use a reverse proxy such as `Apache2` or `nginx` to provide a TLS connection to clients.
Alternatively, you could run `reseed-tools` as an `.onion` service and rely on Tor for encryption and authentication.

You can disable automatic TLS configuration with the `--trustProxy` flag like this:

```sh

./reseed-tools reseed --signer=you@mail.i2p --netdb=/home/i2p/.i2p/netDb --trustProxy --ip=127.0.0.1
```

Setup Self-Signed TLS non-interactively
---------------------------------------

If you don't want to interactively configure TLS but still want to use self-signed certificates, you can pass the `--yes` flag, which will use the defaults for all config values.

```sh

./reseed-tools reseed --signer=you@mail.i2p --netdb=/home/i2p/.i2p/netDb --yes
```

Use ACME to acquire TLS certificate
-----------------------------------

Instead of self-signed certificates, if you want to chain up to a TLS CA, you can.
To automate this process using an ACME CA, like Let's Encrypt, you can use the `--acme` flag.
Be sure to change the `--acmeserver` option in order to use a **production** ACME server, as
the software defaults to a **staging** ACME server for testing purposes.

This functionality is new and may have issues. Please file bug reports at [i2pgit](https://i2pgit.org/go-i2p/reseed-tools) or [github](https://github.com/go-i2p/reseed-tools).

```sh

./reseed-tools reseed --signer=you@mail.i2p --netdb=/home/i2p/.i2p/netDb --acme --acmeserver="https://acme-v02.api.letsencrypt.org/directory"
```
