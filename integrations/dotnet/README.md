# Vpnless.Client.Auth (.NET)

Same session HMAC as [`vpnless-client-auth.js`](../../vpnless-client-auth.js) and [`session_auth.go`](../../session_auth.go): message `v1|` + Unix ts string, HMAC-SHA256 with the base64-decoded pairing secret, headers `X-Device-Public-Key`, `X-Session-Timestamp`, `X-Session-Proof`.

Wire it from the Jellyfin plugin or any .NET host; other stacks should copy the algorithm (see Android bits under `integrations/jellyfin-client`).

```bash
dotnet build integrations/dotnet/Vpnless.Client.Auth.sln -c Release
dotnet test integrations/dotnet/Vpnless.Client.Auth.sln -c Release
```

Library is **net8.0**; Jellyfin plugin stays **net9.0** and references this DLL.
