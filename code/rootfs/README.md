# Password

Replace the `shadow` file in `package/base-files/files/etc/`

# Firewall

Put the following lines to package/network/config/firewall/files/firewall.config

```
config rule
        option name     Allow-SSH
        option src      wan
        option proto    tcp
        option dest_port        22
        option target   ACCEPT

config rule
        option name     Allow-Telnet
        option src      wan
        option proto    tcp
        option dest_port        23
        option target   ACCEPT
```

# Network

Put `network` to `target/linux/ARCH/base-files/etc/config`

# Report

Put `report.sh` to `package/base-files/files/usr/bin`
Replace the `rc.local` file in `package/base-files/files/etc/`
