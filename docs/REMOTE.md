Using a remote Network Database
===============================

Beginning in `reseed-tools 0.2.5` it is possible to use reseed-tools to "share" a netDb directory on one host with a reseed server on another host.
This feature is built into the reseed-tools software.
It is also possible to do this manually using `sshfs`, `ssh` combined with `cron`, and most available backup utilities like `borg` and `syncthing`.
This guide only covers `reseed-tools`.
It requires only `reseed-tools` and an I2P router.
Presumably, if you are reading this document, you are already comfortable running both of these pieces of software.

Why?
----

In most setups, a reseed service is using a network database which is kept on the same server as the I2P router where it finds it's netDb.
This is convenient, however if reseed servers are targeted for a RouterInfo spam attack, then the reseed server could potentially be overwhelmed with spammy RouterInfos.
That impairs a new user's ability to join the network and slows down network integration.

Password-Protected Sharing of NetDB content over I2P
----------------------------------------------------

This method uses SAMv3 via the `onramp` library with `wide` tunnel options(1 hop, 2 tunnels) on both sides.
By using I2P, this method trades some performance for ofuscation.
However, the data is tiny so in-practice it works very well.

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
