
VERSION=$(shell /usr/bin/go run . version 2>/dev/null)
APP=reseed-tools
USER_GH=eyedeekay
SIGNER=hankhill19580@gmail.com
CGO_ENABLED=0
export CGO_ENABLED=0
PLUGIN_PORT=7671
export PLUGIN_PORT=7671
prefix?=/

GOOS?=$(shell uname -s | tr A-Z a-z)
GOARCH?="amd64"

ARG=-v -tags netgo,osusergo -ldflags '-w -extldflags "-static"'

#MIN_GO_VERSION=`ls /usr/lib/go-1.14 2>/dev/null >/dev/null && echo 1.14`
MIN_GO_VERSION?=1.16

I2P_UID=$(shell id -u i2psvc)
I2P_GID=$(shell id -g i2psvc)

WHOAMI=$(shell whoami)

echo:
	@echo "type make version to do release '$(APP)' '$(VERSION)' $(GOOS) $(GOARCH) $(MIN_GO_VERSION) $(I2P_UID) $(I2P_GID)"

host:
	/usr/bin/go build -o reseed-tools-host 2>/dev/null 1>/dev/null

index:
	edgar

build:
	/usr/bin/go build $(ARG) -o reseed-tools-$(GOOS)-$(GOARCH)

1.15-build: gofmt
	/usr/lib/go-$(MIN_GO_VERSION)/bin/go build $(ARG) -o reseed-tools-$(GOOS)-$(GOARCH)

clean:
	rm reseed-tools-* tmp -rfv *.deb plugin reseed-tools

tar:
	git pull github --tags; true
	git pull --tags; true
	git archive --format=tar.gz --output=reseed-tools.tar.gz v$(VERSION)

install:
	install -m755 reseed-tools-$(GOOS)-$(GOARCH) ${prefix}usr/bin/reseed-tools
	install -m644 etc/default/reseed ${prefix}etc/default/reseed
	install -m755 etc/init.d/reseed ${prefix}etc/init.d/reseed
	install -g i2psvc -o i2psvc -D -d ${prefix}var/lib/i2p/i2p-config/reseed/
	install -g i2psvc -o i2psvc -D -d ${prefix}etc/systemd/system/reseed.service.d/
	install -m644 etc/apparmor.d/usr.bin.reseed-tools ${prefix}etc/apparmor.d/usr.bin.reseed-tools
	install -m644 etc/apparmor.d/local/usr.bin.reseed-tools ${prefix}etc/apparmor.d/local/usr.bin.reseed-tools
	install -m644 etc/systemd/system/reseed.service.d/override.conf ${prefix}etc/systemd/system/reseed.service.d/override.conf
	install -m644 etc/systemd/system/reseed.service ${prefix}etc/systemd/system/reseed.service

uninstall:
	rm -rf ${prefix}bin/reseed-tools
	rm -rf ${prefix}etc/default/reseed
	rm -rf ${prefix}etc/init.d/reseed
	rm -rf ${prefix}etc/apparmor.d/usr.bin.reseed-tools
	rm -rf ${prefix}etc/apparmor.d/local/usr.bin.reseed-tools
	rm -rf ${prefix}etc/systemd/system/reseed.service.d/reseed.conf
	rm -rf ${prefix}etc/systemd/system/reseed.service
	rm -rf ${prefix}var/lib/i2p/i2p-config/reseed/

checkinstall:
	checkinstall -D \
		--arch=$(GOARCH) \
		--default \
		--install=no \
		--fstrans=yes \
		--pkgname=reseed-tools \
		--pkgversion=$(VERSION) \
		--pkggroup=net \
		--pkgrelease=1 \
		--pkgsource="https://i2pgit.org/idk/reseed-tools" \
		--maintainer="$(SIGNER)" \
		--requires="i2p,i2p-router" \
		--suggests="i2p,i2p-router,syndie,tor,tsocks" \
		--nodoc \
		--deldoc=yes \
		--deldesc=yes \
		--backup=no

### You shouldn't need to use these now that the go mod require rule is fixed,
## but I'm leaving them in here because it made it easier to test that both
## versions behaved the same way. -idk

build-fork:
	/usr/lib/go-$(MIN_GO_VERSION)/bin/go build -o reseed-tools-idk

build-unfork:
	/usr/lib/go-$(MIN_GO_VERSION)/bin/go build -o reseed-tools-md

fork:
	sed -i 's|idk/reseed-tools|idk/reseed-tools|g' main.go cmd/*.go reseed/*.go su3/*.go
	make gofmt build-fork

unfork:
	sed -i 's|idk/reseed-tools|idk/reseed-tools|g' main.go cmd/*.go reseed/*.go su3/*.go
	sed -i 's|RTradeLtd/reseed-tools|idk/reseed-tools|g' main.go cmd/*.go reseed/*.go su3/*.go
	make gofmt build-unfork

gofmt:
	find . -name '*.go' -exec gofumpt -w -s -extra {} \;

export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64/jre/
export CGO_CFLAGS=-I/usr/lib/jvm/java-8-openjdk-amd64/include/ -I/usr/lib/jvm/java-8-openjdk-amd64/include/linux/

gojava:
	go get -u -v github.com/sridharv/gojava
	cp -v ~/go/bin/gojava ./gojava

jar: gojava
	echo $(JAVA_HOME)
	./gojava -v -o reseed.jar -s . build ./reseed

release: version plugins upload-su3s

version:
	head -n 5 README.md | github-release release -s $(GITHUB_TOKEN) -u $(USER_GH) -r $(APP) -t v$(VERSION) -d -; true

delete-version:
	github-release delete -s $(GITHUB_TOKEN) -u $(USER_GH) -r $(APP) -t v$(VERSION)

edit:
	cat README.md | github-release edit -s $(GITHUB_TOKEN) -u $(USER_GH) -r $(APP) -t v$(VERSION) -d -

plugins:
	#export GOOS=darwin; export GOARCH=amd64; make su3s
	#export GOOS=darwin; export GOARCH=arm64; make su3s
	export GOOS=linux; export GOARCH=amd64; make su3s
	export GOOS=linux; export GOARCH=386; make su3s
	export GOOS=linux; export GOARCH=arm; make su3s
	export GOOS=linux; export GOARCH=arm64; make su3s
	export GOOS=openbsd; export GOARCH=amd64; make su3s
	export GOOS=freebsd; export GOARCH=386; make su3s
	export GOOS=freebsd; export GOARCH=amd64; make su3s
	export GOOS=windows; export GOARCH=amd64; make su3s
	export GOOS=windows; export GOARCH=386; make su3s

debs:
	export GOOS=linux; export GOARCH=amd64; make build checkinstall
	export GOOS=linux; export GOARCH=386; make build checkinstall
	export GOOS=linux; export GOARCH=arm; make build checkinstall
	export GOOS=linux; export GOARCH=arm64; make build checkinstall

rm-su3s:
	rm *.su3 -f

download-su3s:
	#export GOOS=darwin; export GOARCH=amd64; make download-single-su3
	#export GOOS=darwin; export GOARCH=arm64; make download-single-su3
	export GOOS=linux; export GOARCH=386; make download-single-su3
	export GOOS=linux; export GOARCH=amd64; make download-single-su3
	export GOOS=linux; export GOARCH=arm; make download-single-su3
	export GOOS=linux; export GOARCH=arm64; make download-single-su3
	export GOOS=openbsd; export GOARCH=amd64; make download-single-su3
	export GOOS=freebsd; export GOARCH=386; make download-single-su3
	export GOOS=freebsd; export GOARCH=amd64; make download-single-su3
	export GOOS=windows; export GOARCH=amd64; make download-single-su3
	export GOOS=windows; export GOARCH=386; make download-single-su3

upload-su3s:
	#export GOOS=darwin; export GOARCH=amd64; make upload-single-su3
	#export GOOS=darwin; export GOARCH=arm64; make upload-single-su3
	export GOOS=linux; export GOARCH=386; make upload-single-su3
	export GOOS=linux; export GOARCH=amd64; make upload-single-su3
	export GOOS=linux; export GOARCH=arm; make upload-single-su3
	export GOOS=linux; export GOARCH=arm64; make upload-single-su3
	export GOOS=openbsd; export GOARCH=amd64; make upload-single-su3
	export GOOS=freebsd; export GOARCH=386; make upload-single-su3
	export GOOS=freebsd; export GOARCH=amd64; make upload-single-su3
	export GOOS=windows; export GOARCH=amd64; make upload-single-su3
	export GOOS=windows; export GOARCH=386; make upload-single-su3

download-single-su3:
	wget-ds "https://github.com/eyedeekay/reseed-tools/releases/download/v$(VERSION)/reseed-tools-$(GOOS)-$(GOARCH).su3"

upload-single-su3:
	github-release upload -s $(GITHUB_TOKEN) -u $(USER_GH) -r $(APP) -t v$(VERSION) -f reseed-tools-"$(GOOS)"-"$(GOARCH).su3" -l "`sha256sum reseed-tools-$(GOOS)-$(GOARCH).su3`" -n "reseed-tools-$(GOOS)"-"$(GOARCH).su3"; true

tmp/content:
	mkdir -p tmp
	cp -rv reseed/content tmp/content
	echo "you@mail.i2p" > tmp/signer

tmp/lib:
	mkdir -p tmp/lib
#	cp "$(HOME)/build/shellservice.jar" tmp/lib/shellservice.jar

tmp/LICENSE:
	cp LICENSE tmp/LICENSE

SIGNER_DIR=$(HOME)/i2p-go-keys/

su3s: tmp/content tmp/lib tmp/LICENSE build
	rm -f plugin.yaml client.yaml
	i2p.plugin.native -name=reseed-tools-$(GOOS)-$(GOARCH) \
		-signer=hankhill19580@gmail.com \
		-signer-dir=$(SIGNER_DIR) \
		-version "$(VERSION)" \
		-author=hankhill19580@gmail.com \
		-autostart=true \
		-clientname=reseed-tools-$(GOOS)-$(GOARCH) \
		-command="reseed-tools-$(GOOS)-$(GOARCH) reseed --yes --signer=\$$PLUGIN/signer --port=$(PLUGIN_PORT)" \
		-consolename="Reseed Tools" \
		-consoleurl="https://127.0.0.1:$(PLUGIN_PORT)" \
		-updateurl="http://idk.i2p/reseed-tools/reseed-tools-$(GOOS)-$(GOARCH).su3" \
		-website="http://idk.i2p/reseed-tools/" \
		-icondata="content/images/reseed-icon.png" \
		-delaystart="1" \
		-desc="`cat description-pak`" \
		-exename=reseed-tools-$(GOOS)-$(GOARCH) \
		-targetos="$(GOOS)" \
		-res=tmp/ \
		-license=MIT
	#unzip -o reseed-tools-$(GOOS)-$(GOARCH).zip -d reseed-tools-$(GOOS)-$(GOARCH)-zip

#export sumbblinux=`sha256sum "../reseed-tools-linux.su3"`
#export sumbbwindows=`sha256sum "../reseed-tools-windows.su3"`
