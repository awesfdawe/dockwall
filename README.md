# dockwall

Simple firewall for Docker to secure your reverse proxy network.

## Why

By default, containers in the same network can communicate with each other. This is fine and necessary for most setups, but you probably don't want something like Huntarr to be able to communicate directly to Vaultwarden, Forgejo, or other sensitive services. 

If Huntarr gets compromised, an attacker can attack your other services just because they all share the same reverse proxy network.

## What dockwall does

Dockwall sets iptables rules to prevent containers from communicating with each other on specified networks. And allows:
- A reverse proxy to initiate connections to containers (while blocking inter-service traffic).
- Containers to initiate connections only to a specific container on that network (e.g. an xray-core / VPN client).

## Requirements

The `br_netfilter` kernel module must be loaded on the host.

## Configuration

`config.yaml`:

```yaml
debounce: 500ms # Wait 500ms after Docker events before applying rules
poll_interval: 1m # Periodic check to ensure rules remain intact

policies:
  - network: proxy # Name of the Docker network
    rules:
      - from: reverse-proxy # container name or "*"
        to: "*" # container name or "*"

  - network: bypass
    rules:
      - from: "*"
        to: xray-core
```

## Setup

`docker-compose.yaml`:

```yaml
services:
  dockwall:
    image: ghcr.io/awesfdawe/dockwall:latest
    container_name: dockwall
    restart: unless-stopped
    network_mode: host # required to manage iptables rules
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN # required for iptables
    security_opt:
      - no-new-privileges:true
    read_only: true
    userns_mode: host # required if user remap enabled
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./config.yaml:/etc/dockwall/config.yaml:ro
```

```bash
docker compose up -d
```

## Security of this project

This container doesn't connect to the internet. GO builds are fully reproducible. The code is just ~600 lines (excluding tests and empty lines).

## Inspect rules

```bash
iptables -L DOCKWALL -v -n --line-numbers
```
