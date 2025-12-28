# syntax=docker/dockerfile:1

FROM ubuntu:24.04

RUN apt-get update && apt-get -y upgrade

# Install deb package but ignore daemon dependency
COPY scion++-tools_0.0.1-1_amd64.deb /
COPY scitra-tun_0.0.1-1_amd64.deb /
RUN apt-get install -y /scion++-tools_0.0.1-1_amd64.deb /scitra-tun_0.0.1-1_amd64.deb

ENTRYPOINT ["scitra-tun"]
CMD ["lo", "127.0.0.1"]
