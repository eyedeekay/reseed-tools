# Service Integration

Support for running as a system service as part of the reseed package
is new. PR's that improve integration are welcome.

## Systemd Service

A systemd service is provided which should work with the I2P Debian package
when reseed-tools is installed in `/usr/bin/reseed-tools`. If you install with
`make install` this service is also installed. This service will cause the
bundles to regenerate every 12 hours.

The contact email for your reseed should be added in:
`/etc/systemd/system/reseed.service.d/override.conf`.

Self-signed certificates will be auto-generated for these services. To change
this you should edit the `/etc/systemd/system/reseed.service`. For instance:

```
ExecStart=/usr/bin/reseed-tools reseed --yes=true --netdb=/var/lib/i2p/i2p-config/netDb --trustProxy --ip=127.0.0.1
```

to disable self-signed certificate generation.

- To enable starting the reseed service automatically with the system: `sudo systemctl enable reseed.service`
- To run the service manually: `sudo systemctl start reseed.service`  
- To reload the systemd services: `sudo systemctl daemon-reload`
- To view the status/logs: `sudo journalctl -u reseed.service`

## SysV Service

An initscript is also provided. The initscript, unlike the systemd service,
cannot schedule itself to restart. You should restart the service roughly once
a day to ensure that the information does not expire.

The contact email for your reseed should be added in:
`/etc/default/reseed`.

Self-signed certificates will be auto-generated for these services.
To change this you should edit the `/etc/default/reseed`.
Create a `MORE_OPTIONS=""` field. For instance:

```sh
MORE_OPTIONS="--trustProxy --ip=127.0.0.1"
```

will disable self-signed certificate generation.
