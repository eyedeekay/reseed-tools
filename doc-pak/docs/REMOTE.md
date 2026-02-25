Using a remote Network Database
-------------------------------

Beginning in `reseed-tools 0.2.5` it is possible to use reseed-tools to "share" a netDb directory on one host with a reseed server on another host.
This feature is built into the reseed-tools software.
It is also possible to do this manually using `sshfs`, `ssh` combined with `cron`, and most available backup utilities like `borg` and `syncthing`.
This guide only covers `reseed-tools`.

Password-Protected Sharing of NetDB content over I2P
----------------------------------------------------

Run this command on a well-integrated I2P router which is **not** hosting a reseed server on the same IP address.
To share the whole contents of your netDb directory over I2P, run reseed-tools with the following arguments:

```sh
reseed-tools share --share-password $(use_a_strong_password) --netdb $(path_to_your_netdb)
```

In a few seconds, you will have a new I2P site which will provide your netDb as a `.tar.gz` file to anyone with the password.
Make a note of the base32 address of the new site for the next step.

Password-Protected Retrieval of Shared NetDB content over I2P
-------------------------------------------------------------

Run this command on a router hosting which **is** hosting a reseed server on the same IP address, or add the arguments to your existing command.
To retrieve a remote NetDB bundle from a hidden service, run reseed tools with the following arguments:

```sh
reseed-tools reseed --share-peer $(thebase32addressyoumadeanoteofaboveintheotherstepnow.b32.i2p) --share-password $(use_a_strong_password) --netdb $(path_to_your_netdb)
```

Periodically, the remote `netdb.tar.gz` bundle will be fetched from the remote server and extracted to the `--netdb` directory.
If the `--netdb` directory is not empty, local RI's are left intact and never overwritten, essentially combining the local and remote netDb.
If the directory is empty, the remote netDb will be the only netDb used by the reseed server.
