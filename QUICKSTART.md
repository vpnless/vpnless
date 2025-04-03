# Quick start

You need Go 1.21+ and `xcaddy` (`go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest`).

**Build**

```bash
make build-caddy
make build-cli
# or: xcaddy build --with github.com/vpnless/vpnless
#     go build -o vpnless ./cmd/vpnless-cli
```

**Minimal Caddyfile** — only `approval_basic_auth` is required; everything else has defaults.

```caddyfile
localhost:8080 {
    device_auth {
        approval_basic_auth admin:password123
    }

    respond "Hello, authenticated user!"
}
```

Run `./caddy run`, hit `http://localhost:8080`, get sent to pairing, then open the approval URL from your config (examples often use `/caddy-auth`; defaults in-tree may be `/vpnless/admin`) and log in as `admin` / `password123`, approve the device, come back — you should see the hello response.

**CLI instead of the web UI**

```bash
./vpnless list pending
./vpnless approve <device-id>
```

**curl with Ed25519 headers** — generate keys in your test harness, then:

```bash
curl -H "X-Device-Public-Key: <base64-public-key>" \
     -H "X-Device-Sig: <base64-signature>" \
     -H "X-Device-Timestamp: $(date +%s)" \
     http://localhost:8080/
```

That lands the device in pending; approve via UI or CLI.

**When something breaks**

- `module not found` → fix the `module` line in `go.mod` if you forked under another path.
- DB permission errors → same as any SQLite file: writable directory, sane `chmod` on `*.db`.
- Caddy exits → `./caddy run --config Caddyfile` and read what it prints.

More detail: [README.md](README.md), sample knobs in [Caddyfile.example](Caddyfile.example). Pairing/admin markup is in `templates.go` if you want to hack the HTML.
