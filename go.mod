module i2pgit.org/idk/reseed-tools

go 1.13

require (
	github.com/cretz/bine v0.2.0
	github.com/eyedeekay/checki2cp v0.0.21
	github.com/eyedeekay/go-i2pd v0.0.0-20220213070306-9807541b2dfc
	github.com/eyedeekay/sam3 v0.32.32
	github.com/go-acme/lego/v4 v4.3.1
	github.com/gorilla/handlers v1.5.1
	github.com/hjson/hjson-go v3.1.0+incompatible
	github.com/justinas/alice v1.2.0
	github.com/libp2p/go-libp2p v0.13.0
	github.com/libp2p/go-libp2p-core v0.8.0
	github.com/libp2p/go-libp2p-gostream v0.3.1
	github.com/libp2p/go-libp2p-http v0.2.0
	github.com/mitchellh/mapstructure v1.4.1
	github.com/throttled/throttled/v2 v2.7.1
	github.com/urfave/cli v1.22.5
	github.com/yggdrasil-network/yggdrasil-go v0.4.3
	gitlab.com/golang-commonmark/markdown v0.0.0-20191127184510-91b5b3c99c19
	golang.org/x/text v0.3.8-0.20211004125949-5bd84dd9b33b
)

replace github.com/libp2p/go-libp2p => github.com/libp2p/go-libp2p v0.13.0

replace github.com/libp2p/go-libp2p-core => github.com/libp2p/go-libp2p-core v0.8.0

replace github.com/libp2p/go-libp2p-gostream => github.com/libp2p/go-libp2p-gostream v0.3.1

replace github.com/libp2p/go-libp2p-http => github.com/libp2p/go-libp2p-http v0.2.0

replace github.com/eyedeekay/go-i2pd v0.0.0-20220213070306-9807541b2dfc => ./go-i2pd
