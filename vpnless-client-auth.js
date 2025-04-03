// Patches fetch() to add X-Session-Proof / timestamp (HMAC from pairing secret). Keys must match
// the pairing page: device_auth_keypair, device_auth_session_secret.
//   <script src="/vpnless-client-auth.js"></script>
//   <script>VPNLessFetchAuth.install({ sameOriginOnly: true });</script>
(function (global) {
    'use strict';

    var STORAGE_KEY = 'device_auth_keypair';
    var STORAGE_SESSION_SECRET = 'device_auth_session_secret';

    function sameOrigin(urlStr, baseLoc) {
        try {
            var u = new URL(urlStr, baseLoc || global.location.href);
            return u.origin === global.location.origin;
        } catch (e) {
            return false;
        }
    }

    function mergeInitHeaders(init, extra) {
        init = init || {};
        var h = init.headers;
        if (typeof Headers !== 'undefined' && h instanceof Headers) {
            Object.keys(extra).forEach(function (k) {
                if (!h.has(k)) h.set(k, extra[k]);
            });
            return init;
        }
        var out = Object.assign({}, extra);
        if (h && typeof h === 'object' && !(h instanceof Headers)) {
            Object.keys(h).forEach(function (k) {
                if (out[k] === undefined) out[k] = h[k];
            });
        }
        init.headers = out;
        return init;
    }

    async function computeClientSessionProof(secretB64, timestamp) {
        var msg = new TextEncoder().encode('v1|' + timestamp);
        var bin = atob(secretB64);
        var keyRaw = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) keyRaw[i] = bin.charCodeAt(i);
        var key = await crypto.subtle.importKey('raw', keyRaw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        var sig = await crypto.subtle.sign('HMAC', key, msg);
        var bytes = new Uint8Array(sig);
        var s = '';
        for (var j = 0; j < bytes.length; j++) s += String.fromCharCode(bytes[j]);
        return btoa(s);
    }

    async function buildSessionHeaders() {
        if (!global.crypto || !global.crypto.subtle) return {};
        var secret = null;
        var raw = null;
        try {
            secret = global.localStorage.getItem(STORAGE_SESSION_SECRET);
            raw = global.localStorage.getItem(STORAGE_KEY);
        } catch (e) {
            return {};
        }
        if (!secret || !raw) return {};
        var keypair;
        try {
            keypair = JSON.parse(raw);
        } catch (e) {
            return {};
        }
        if (!keypair || !keypair.publicKey) return {};
        var ts = Math.floor(Date.now() / 1000).toString();
        var proof = await computeClientSessionProof(secret, ts);
        return {
            'X-Device-Public-Key': keypair.publicKey,
            'X-Session-Timestamp': ts,
            'X-Session-Proof': proof
        };
    }

    /** Same shape as window.deviceAuthSessionHeaders on the pairing page. */
    async function deviceAuthSessionHeaders() {
        return buildSessionHeaders();
    }

    var installed = false;

    global.VPNLessFetchAuth = {
        install: function (opts) {
            if (installed) return;
            installed = true;
            opts = opts || {};
            var sameOnly = opts.sameOriginOnly !== false;
            var origFetch = global.fetch;
            if (typeof origFetch !== 'function') return;

            global.fetch = async function (input, init) {
                var urlStr = typeof input === 'string' ? input : input && input.url;
                if (sameOnly && urlStr && !sameOrigin(urlStr)) {
                    return origFetch.call(this, input, init);
                }
                var sh = await buildSessionHeaders();
                if (!sh || !sh['X-Session-Proof']) {
                    return origFetch.call(this, input, init);
                }
                init = mergeInitHeaders(init ? Object.assign({}, init) : {}, sh);
                return origFetch.call(this, input, init);
            };
        },

        sessionHeaders: deviceAuthSessionHeaders,
        STORAGE_KEY: STORAGE_KEY,
        STORAGE_SESSION_SECRET: STORAGE_SESSION_SECRET
    };

    // Pairing page compatibility: mirror the global the inline pairing script defines.
    if (!global.deviceAuthSessionHeaders) {
        global.deviceAuthSessionHeaders = deviceAuthSessionHeaders;
    }
})(typeof window !== 'undefined' ? window : typeof self !== 'undefined' ? self : this);
