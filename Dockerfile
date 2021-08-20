FROM debian:stable-backports
ARG I2P_GID=1000
ARG I2P_UID=1000
COPY . /var/lib/i2p/go/src/i2pgit.org/idk/reseed-tools
WORKDIR /var/lib/i2p/go/src/i2pgit.org/idk/reseed-tools
RUN apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install -y git golang-go make && \
    mkdir -p /var/lib/i2p/i2p-config/reseed && \
    chown -R $I2P_UID:$I2P_GID /var/lib/i2p && chmod -R o+rwx /var/lib/i2p
RUN go build -v -tags netgo -ldflags '-w -extldflags "-static"'
USER $I2P_UID
WORKDIR /var/lib/i2p/i2p-config/reseed
ENTRYPOINT [ "/var/lib/i2p/go/src/i2pgit.org/idk/reseed-tools/entrypoint.sh" ]