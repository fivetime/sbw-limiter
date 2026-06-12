# VPP 26.06 (stable/2606) functional-test image, built from .deb packages
# produced from the vetted VPP source tree (`make pkg-deb`). Build context must
# contain the .deb files under ./debs/.
#
#   make -C <vpp-src> pkg-deb
#   cp <vpp-src>/build-root/*.deb bwpool/deploy/vpp/debs/
#   docker build -t bwpool/vpp:26.06 bwpool/deploy/vpp
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

COPY debs/*.deb /tmp/debs/
RUN apt-get update \
 && apt-get install -y /tmp/debs/*.deb \
 && rm -rf /tmp/debs /var/lib/apt/lists/*

RUN groupadd -f vpp && mkdir -p /run/vpp /var/log/vpp

COPY startup.conf /etc/vpp/startup.conf

# vpp runs in the foreground (unix { nodaemon }); the binary API socket appears
# at /run/vpp/api.sock for the edge-agent.
ENTRYPOINT ["/usr/bin/vpp", "-c", "/etc/vpp/startup.conf"]
