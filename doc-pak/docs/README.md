Configure an I2P Reseed Server Very Rapidly on Debian and Ubuntu
================================================================

It is possible to easily and automatically configure a reseed server
with a self-signed certificate on any Debian-based operating system,
including Ubuntu and it's downstreams. This is achieved using the `checkinstall`
tool to set up the software dependencies and the operating system to
run the `I2P` service and the `reseed` service.

Using a binary package
----------------------

If you do not wish to build from source, you can use a binary package
from me. This package is built from this repo with the `make checkinstall`
target and uploaded by me. I build it on an up-to-date Debian `sid` system
at tag time. It contains a static binary and files for configuring it as a
system service.

```sh

wget https://github.com/go-i2p/reseed-tools/releases/download/v0.2.30/reseed-tools_0.2.30-1_amd64.deb
# Obtain the checksum from the release web page
echo "38941246e980dfc0456e066f514fc96a4ba25d25a7ef993abd75130770fa4d4d reseed-tools_0.2.30-1_amd64.deb" > SHA256SUMS
sha256sums -c SHA256SUMS
sudo apt-get install ./reseed-tools_0.2.30-1_amd64.deb
```

Building the `.deb` package from the source(Optional)
-----------------------------------------------------

If your software is too old, it's possible that the binary package I build will
not work for you. It's very easy to generate your own from the source code in this
repository.

\\**1.** Install the build dependencies

```sh

sudo apt-get install fakeroot checkinstall go git make
```

\\**2.** Clone the source code

```sh

git clone https://i2pgit.org/go-i2p/reseed-tools ~/go/src/i2pgit.org/go-i2p/reseed-tools
```

\\**3.** Generate the `.deb` package using the `make checkinstall` target

```sh

cd ~/go/src/i2pgit.org/go-i2p/reseed-tools
make checkinstall
```

\\**4.** Install the `.deb` package

```sh

sudo apt-get install ./reseed-tools_*.deb
```

Running the Service
-------------------

\\**1.** First, ensure that the I2P service is already running. The longer the better,
if you have to re-start the service, or if the service has very few peers, allow it to
run for 24 hours before advancing to step **2.**

```sh

sudo systemctl start i2p
# or, if you use sysvinit
sudo service i2p start
```

\\**2.** Once your I2P router is "Well-Integrated," start the reseed service.

```sh

sudo systemctl start reseed
# or, if you use sysvinit
sudo service reseed start
```

Your reseed will auto-configure with a self-signed certificate on port `:8443`. The
certificates themselves are available in `/var/lib/i2p/i2p-config/reseed`. When
you are ready, you should copy the `*.crt` files from that directory and share them
witth the I2P community on [`zzz.i2p`](http://zzz.i2p). These will allow I2P users
to authenticate your reseed services and secure the I2P network.
