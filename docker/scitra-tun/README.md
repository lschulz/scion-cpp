Scitra-TUN Docker Container
===========================

Docker container and compose file that run scitra-tun in the host system's network context, but
without requiring dependencies on the host except for Docker and the SCION Daemon.

Building the image require the scitra-tun Debian packages in the build context:
```bash
cp ../../out/scion++-tools_0.0.1-1_amd64.deb ./scitra-tun
cp ../../out/scitra-tun_0.0.1-1_amd64.deb ./scitra-tun
docker compose build
```

Scitra-TUN is configured in the compose file. Set `SCION_DAEMON_ADDRESS` to the address of the SCION
Daemon on the host and configure at least the interface and address parameters in the `command`
string.

Running Scitra-TUN in the background is then accomplished by
```bash
docker compose up -d
```
