# **VPNLESS**: the **REVERSE PROXY** exclusively for **SELF HOSTERS**

- No separate VPN client software layer, no additional helper apps
- Easy enough for kids and grandparents to use
- Easy for parents to admin
- Secure defaults, easy first run.
- Keep setup boring: one DNS record, one compose path, minimal config.
- Caddy's SSL without maintaining Caddyfile or DNS
- Enjoy torturing bots and hackers trying to sneak in

Self Hosting focused Reverse Proxy based on Caddy, configured via docker labels, and providing some security without external dependencies like Tailscale

## INSTALLING

1. Install docker
2. `docker network create vpnless`
3. Install vpnless


# Docker Setup

### Portainer

```
docker run -d --name portainer \
   --restart always -v /var/run/docker.sock:/var/run/docker.sock \
   -v portainer_data:/data \
   --label caddy.vpnless= \
   --label caddy.reverse_proxy="{{upstreams 9000}}" \
   --label caddy=portainer.example.com \
   --label homepage.href=https://portainer.example.com \
   --label homepage.group=Infrastructure \
   --label homepage.name=Portainer \
   --label homepage.icon=portainer \
   --label homepage.description="Docker Container Management" \
   portainer/portainer-ce:latest
```

## Compare to:

https://github.com/tailscale/tailscale
https://headscale.net/stable/
https://github.com/jsiebens/ionscale
https://github.com/slackhq/nebula
https://pangolin.net/product
https://netbird.io/

## License

OS.Cash Free License
