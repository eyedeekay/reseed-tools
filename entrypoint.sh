#! /usr/bin/env sh

cp -r /var/lib/i2p/go/src/github.com/idk/reseed-tools/content ./content

/var/lib/i2p/go/src/github.com/idk/reseed-tools/i2p-tools-1 reseed --yes=true --netdb=/var/lib/i2p/i2p-config/netDb $@
