package vpnless

const pairingPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Pairing</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        :root {
            --bg-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --surface: #ffffff;
            --text: #333333;
            --muted: #666666;
            --device-bg: #f8f9fa;
            --input-bg: #ffffff;
            --input-text: #20242a;
            --input-border: #ced4da;
            --input-placeholder: #7d8694;
        }
        :root[data-theme="dark"] {
            --bg-gradient: linear-gradient(135deg, #1f2a44 0%, #2a1f3d 100%);
            --surface: #171a20;
            --text: #e6e6e6;
            --muted: #a5adba;
            --device-bg: #222834;
            --input-bg: #0f141b;
            --input-text: #e6e9ee;
            --input-border: #3b4556;
            --input-placeholder: #95a0b2;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: var(--bg-gradient);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: var(--surface);
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            max-width: 560px;
            width: 100%;
            position: relative;
        }
        h1 {
            color: var(--text);
            margin-bottom: 10px;
            font-size: 28px;
        }
        .brand {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
        }
        .brand-logo {
            width: 36px;
            height: 36px;
            object-fit: contain;
        }
        .brand-title {
            margin: 0;
            color: var(--text);
            font-size: 28px;
            line-height: 1.1;
        }
        .subtitle {
            color: var(--muted);
            margin-bottom: 30px;
            font-size: 14px;
        }
        .status {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-weight: 500;
        }
        .status.pending {
            background: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
        }
        .status.authorized {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .status.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .device-id {
            background: var(--device-bg);
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 16px;
            font-weight: bold;
            color: var(--text);
            text-align: center;
            margin: 20px 0;
            word-break: break-all;
        }
        .instructions {
            background: #e7f3ff;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #2196F3;
            margin: 20px 0;
            font-size: 14px;
            line-height: 1.6;
            color: #333;
        }
        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .hidden {
            display: none;
        }
        .device-info {
            background: var(--device-bg);
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 16px;
            margin: 20px 0;
            font-size: 13px;
            line-height: 1.6;
            color: var(--text);
            text-align: left;
        }
        .device-info h3 {
            margin: 0 0 12px 0;
            font-size: 14px;
            color: #495057;
        }
        .device-info dl {
            margin: 0;
            display: grid;
            gap: 4px 16px;
            grid-template-columns: auto 1fr;
        }
        .device-info dt {
            font-weight: 600;
            color: var(--muted);
        }
        .device-info dd {
            margin: 0;
            word-break: break-word;
        }
        .theme-toggle {
            position: absolute;
            top: 12px;
            right: 12px;
            border: 1px solid #ced4da;
            background: transparent;
            color: var(--text);
            border-radius: 6px;
            padding: 6px 10px;
            cursor: pointer;
            font-size: 12px;
        }
        input, textarea {
            background: var(--input-bg);
            color: var(--input-text);
            border: 1px solid var(--input-border);
        }
        input::placeholder, textarea::placeholder {
            color: var(--input-placeholder);
        }
        .pair-request {
            margin: 20px 0;
        }
        .pair-request label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            color: var(--muted);
            margin-bottom: 6px;
        }
        .pair-request input[type="text"] {
            width: 100%;
            padding: 10px 12px;
            border-radius: 8px;
            font-size: 15px;
            margin-bottom: 12px;
        }
        .pair-request button.request-access {
            width: 100%;
            padding: 12px 16px;
            border-radius: 8px;
            border: none;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }
        .pair-request button.request-access:hover {
            filter: brightness(1.05);
        }
        :root[data-theme="dark"] .pair-request button.request-access {
            background: linear-gradient(135deg, #3d4f8f 0%, #5a3d6e 100%);
        }
        .denied-wrap {
            text-align: center;
            padding: 8px 0 4px;
        }
        .denied-hero {
            font-size: 1.65rem;
            font-weight: 700;
            color: var(--text);
            margin-bottom: 8px;
        }
        .denied-snark {
            font-size: 1.08rem;
            color: var(--muted);
            margin: 18px 0;
            line-height: 1.55;
        }
        .denied-custom {
            margin: 20px 0;
            padding: 14px 16px;
            border-radius: 8px;
            background: var(--device-bg);
            border-left: 4px solid #dc3545;
            text-align: left;
            font-size: 15px;
            line-height: 1.5;
            color: var(--text);
            white-space: pre-wrap;
            word-break: break-word;
        }
        .denied-hint {
            font-size: 13px;
            color: var(--muted);
            margin: 22px 0 14px;
            line-height: 1.45;
        }
        .denied-wrap button.try-again {
            width: 100%;
            max-width: 320px;
            margin: 0 auto;
            display: block;
            padding: 12px 16px;
            border-radius: 8px;
            border: none;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
        }
        .denied-wrap button.try-again:hover {
            filter: brightness(1.05);
        }
        :root[data-theme="dark"] .denied-wrap button.try-again {
            background: linear-gradient(135deg, #3d4f8f 0%, #5a3d6e 100%);
        }
        .denied-wrap.denied-permanent .denied-hero {
            color: #b02a37;
        }
        :root[data-theme="dark"] .denied-wrap.denied-permanent .denied-hero {
            color: #ff6b6b;
        }
        .pair-gate-loading {
            text-align: center;
            color: var(--muted);
            font-size: 14px;
            padding: 20px 12px 8px;
        }
        .pair-gate-loading.hidden {
            display: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <button id="themeToggle" class="theme-toggle" type="button">Theme</button>
        <div class="brand">
            <img class="brand-logo" src="/vpnless-icon.svg" alt="VPNLess" />
            <h1 class="brand-title">Device Pairing</h1>
        </div>
        <p class="subtitle">Pair this browser</p>
        <p class="pair-hint" style="font-size:13px;line-height:1.45;margin:8px 0 0;opacity:.92;max-width:36rem;"><strong>Admin approval</strong> uses the name and device details you submit below — same data whether this browser later uses the HTTP-only <strong>cookie</strong> (simple full-page loads) or <strong>session proof</strong> headers via <code>/vpnless-client-auth.js</code> and <code>VPNLessFetchAuth.install({ sameOriginOnly: true })</code> on <code>fetch()</code> (recommended for SPAs and replay resistance). The cookie is convenient but replayable until you disable the device; session proofs send a fresh timestamped HMAC on each request.</p>
        <div id="pairGateLoading" class="pair-gate-loading hidden" aria-live="polite">Checking pairing status…</div>

        <div id="pairingFlow">
        <div id="requestPanel" class="pair-request">
            <label for="displayName">Name <span style="font-weight:400;">(optional)</span></label>
            <input type="text" id="displayName" name="display_name" autocomplete="name" maxlength="128" placeholder="e.g. kid's tablet, work laptop" />
            <button type="button" id="requestBtn" class="request-access">Request access</button>
        </div>
        
        <div id="status" class="status hidden"></div>
        <div id="deviceId" class="device-id hidden"></div>
        <div id="instructions" class="instructions hidden"></div>
        <div id="deviceInfo" class="device-info hidden"></div>
        <div id="spinner" class="spinner hidden"></div>
        </div>

        <div id="deniedPanel" class="denied-wrap hidden">
            <div class="denied-hero">Access denied</div>
            <p id="deniedSnark" class="denied-snark"></p>
            <div id="deniedCustom" class="denied-custom hidden"></div>
            <p id="deniedHint" class="denied-hint">If that was a mistake, you can beg for access again. We are very forgiving. (Once.)</p>
            <button type="button" id="deniedRetry" class="try-again">Request access again</button>
        </div>
    </div>

    <script src="/vpnless-client-auth.js"></script>
    <script>
        window.__SERVER_CLIENT_INFO__=null;
        (function() {
            const THEME_COOKIE = 'vpnless_theme';
            const STORAGE_KEY = 'device_auth_keypair';
            const STORAGE_SESSION_SECRET = 'device_auth_session_secret';
            const API_PATH = '__VPNLESS_PAIRING_API_PATH__';
            const DENY_SNARKS = [
                'The admin has spoken. You are not on the list.',
                'Nope. Nada. Nein. Nyet. Take the hint.',
                'This pairing request has left the chat.',
                'Your device ID was read, judged, and found wanting.',
                'Somewhere an admin smiled. It was not for you.',
                'Denied. Don\'t take it personally — or do, we don\'t care.',
                'The velvet rope stayed closed. Try not to trip on it.',
                'Access is a privilege. Today you brought neither cookies nor credentials.',
                'Rejected faster than a NFT pitch at a funeral.',
                'If this were a club, you\'d still be outside in the rain.',
                'The gatekeeper said "lol no" and we\'re obligated to report that faithfully.',
                'Your key is valid; your vibe is not. (Just kidding — the admin clicked Deny.)',
                'Denied with enthusiasm. Consider this a character-building moment.',
                'We ran the numbers. You were not in them.',
            ];
            let pollTimer = null;

            function cookieGet(name) {
                const p = document.cookie.split(';').map(v => v.trim());
                for (const v of p) if (v.startsWith(name + '=')) return decodeURIComponent(v.slice(name.length + 1));
                return '';
            }
            function cookieSet(name, value) {
                document.cookie = name + '=' + encodeURIComponent(value) + '; path=/; max-age=157680000; samesite=lax';
            }
            function preferredTheme() {
                const saved = cookieGet(THEME_COOKIE);
                if (saved === 'light' || saved === 'dark') return saved;
                return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
            }
            function applyTheme(theme) {
                document.documentElement.setAttribute('data-theme', theme);
                const btn = document.getElementById('themeToggle');
                if (btn) btn.textContent = theme === 'dark' ? 'LIGHT' : 'DARK';
            }
            function initTheme() {
                applyTheme(preferredTheme());
                const btn = document.getElementById('themeToggle');
                if (!btn) return;
                btn.addEventListener('click', function() {
                    const current = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
                    const next = current === 'dark' ? 'light' : 'dark';
                    cookieSet(THEME_COOKIE, next);
                    applyTheme(next);
                });
            }
            
            function persistSessionSecret(data) {
                if (data && data.session_secret) {
                    try {
                        localStorage.setItem(STORAGE_SESSION_SECRET, data.session_secret);
                    } catch (e) { console.warn('Could not store session secret', e); }
                }
            }

            /** Jellyfin VPNLess APK injects [VpnlessAndroid]; hand off credentials so the app can continue in its main WebView. */
            function notifyVpnlessAndroidIfEmbedded() {
                try {
                    if (typeof VpnlessAndroid === 'undefined' || typeof VpnlessAndroid.onPaired !== 'function') {
                        return false;
                    }
                    const raw = localStorage.getItem(STORAGE_KEY);
                    const secret = localStorage.getItem(STORAGE_SESSION_SECRET);
                    if (!raw || !secret) return false;
                    const kp = JSON.parse(raw);
                    if (!kp || !kp.publicKey) return false;
                    VpnlessAndroid.onPaired(JSON.stringify({
                        publicKey: kp.publicKey,
                        sessionSecret: secret
                    }));
                    return true;
                } catch (e) {
                    console.warn('VPNLess Android bridge:', e);
                    return false;
                }
            }
            
            /** Build HMAC-SHA256(secret, "v1|"+timestamp) as base64 — same as server. Secret stays in memory only. */
            async function computeClientSessionProof(secretB64, timestamp) {
                const msg = new TextEncoder().encode('v1|' + timestamp);
                const bin = atob(secretB64);
                const keyRaw = new Uint8Array(bin.length);
                for (let i = 0; i < bin.length; i++) keyRaw[i] = bin.charCodeAt(i);
                const key = await crypto.subtle.importKey('raw', keyRaw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
                const sig = await crypto.subtle.sign('HMAC', key, msg);
                let s = '';
                const bytes = new Uint8Array(sig);
                for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
                return btoa(s);
            }
            
            /** Headers for fetch() when you have the session secret + public key (cookie not required). */
            window.deviceAuthSessionHeaders = async function() {
                const secret = localStorage.getItem(STORAGE_SESSION_SECRET);
                const raw = localStorage.getItem(STORAGE_KEY);
                if (!secret || !raw) return {};
                const keypair = JSON.parse(raw);
                const ts = Math.floor(Date.now() / 1000).toString();
                const proof = await computeClientSessionProof(secret, ts);
                return {
                    'X-Device-Public-Key': keypair.publicKey,
                    'X-Session-Timestamp': ts,
                    'X-Session-Proof': proof
                };
            };
            
            // Load or generate keypair
            function getKeyPair() {
                let keypair = localStorage.getItem(STORAGE_KEY);
                if (keypair) {
                    return JSON.parse(keypair);
                }
                
                // Generate new keypair using Web Crypto API
                return generateKeyPair();
            }
            
            async function generateKeyPair() {
                try {
                    const keyPair = await crypto.subtle.generateKey(
                        {
                            name: "Ed25519",
                            namedCurve: "Ed25519"
                        },
                        true,
                        ["sign", "verify"]
                    );
                    
                    const publicKeyRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
                    const privateKeyRaw = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
                    
                    const publicKeyB64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyRaw)));
                    const privateKeyB64 = btoa(String.fromCharCode(...new Uint8Array(privateKeyRaw)));
                    
                    const keypair = {
                        publicKey: publicKeyB64,
                        privateKey: privateKeyB64,
                        keyPair: keyPair // Keep the CryptoKey for signing
                    };
                    
                    localStorage.setItem(STORAGE_KEY, JSON.stringify({
                        publicKey: keypair.publicKey,
                        privateKey: keypair.privateKey
                    }));
                    
                    return keypair;
                } catch (error) {
                    console.error('Failed to generate keypair:', error);
                    // Fallback: use a simple approach (for browsers without Ed25519 support)
                    return generateKeyPairFallback();
                }
            }
            
            function generateKeyPairFallback() {
                // Simple fallback - in production, you'd want a proper polyfill
                const array = new Uint8Array(32);
                crypto.getRandomValues(array);
                const publicKey = btoa(String.fromCharCode(...array));
                const privateKey = btoa(String.fromCharCode(...array));
                
                const keypair = {
                    publicKey: publicKey,
                    privateKey: privateKey
                };
                
                localStorage.setItem(STORAGE_KEY, JSON.stringify(keypair));
                return keypair;
            }
            
            async function signMessage(privateKeyB64, message) {
                try {
                    // Try Web Crypto API first
                    const keypair = JSON.parse(localStorage.getItem(STORAGE_KEY));
                    if (keypair && keypair.keyPair) {
                        const encoder = new TextEncoder();
                        const signature = await crypto.subtle.sign(
                            "Ed25519",
                            keypair.keyPair.privateKey,
                            encoder.encode(message)
                        );
                        return btoa(String.fromCharCode(...new Uint8Array(signature)));
                    }
                } catch (error) {
                    console.warn('Web Crypto signing failed, using fallback');
                }
                
                // Fallback: send to server for signing (not ideal, but works)
                return null;
            }
            
            function showStatus(message, type) {
                const statusEl = document.getElementById('status');
                statusEl.textContent = message;
                statusEl.className = 'status ' + type;
                statusEl.classList.remove('hidden');
            }
            
            function showDeviceID(deviceID) {
                const deviceIdEl = document.getElementById('deviceId');
                deviceIdEl.textContent = 'Device ID: ' + deviceID;
                deviceIdEl.classList.remove('hidden');
            }
            
            function showInstructions(message) {
                const instructionsEl = document.getElementById('instructions');
                instructionsEl.textContent = message;
                instructionsEl.classList.remove('hidden');
            }
            
            async function getClientDeviceInfo() {
                const info = {};
                info.user_agent = navigator.userAgent;
                info.language = navigator.language;
                info.languages = navigator.languages ? navigator.languages.join(', ') : '';
                info.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
                info.screen = screen.width + '×' + screen.height + ' (' + screen.colorDepth + '-bit)';
                info.hardware_concurrency = navigator.hardwareConcurrency || '—';
                if (navigator.deviceMemory) info.device_memory_gb = navigator.deviceMemory;
                if (navigator.plugins && navigator.plugins.length > 0) {
                    const names = Array.from(navigator.plugins).map(p => p.name).filter(n => n);
                    const trivial = new Set(['PDF Viewer', 'Chrome PDF Viewer', 'Chromium PDF Viewer', 'Microsoft Edge PDF Viewer', 'WebKit built-in PDF', 'PDF Plugin', 'Native Client']);
                    const nonTrivial = names.filter(n => !trivial.has(n));
                    if (nonTrivial.length > 0) info.plugins = nonTrivial.join(', ');
                }
                if (navigator.userAgentData) {
                    const ua = navigator.userAgentData;
                    info.mobile = ua.mobile;
                    info.platform = ua.platform;
                    if (ua.brands && ua.brands.length) {
                        info.browser_brands = ua.brands.map(b => b.brand + (b.version ? '/' + b.version : '')).join(', ');
                    }
                    try {
                        const high = await ua.getHighEntropyValues(['uaFullVersion', 'platformVersion', 'architecture', 'model']);
                        if (high.uaFullVersion) info.ua_full_version = high.uaFullVersion;
                        if (high.platformVersion) info.platform_version = high.platformVersion;
                        if (high.architecture) info.architecture = high.architecture;
                        if (high.model) info.model = high.model;
                    } catch (e) {}
                }
                return info;
            }
            
            function renderDeviceInfo(deviceID, serverInfo, clientInfo) {
                const frag = [];
                frag.push('<h3>This device</h3><dl>');
                if (serverInfo && serverInfo.remote_addr) frag.push('<dt>IP address</dt><dd>' + escapeHtml(serverInfo.remote_addr) + '</dd>');
                frag.push('<dt>Device ID</dt><dd>' + escapeHtml(deviceID) + '</dd>');
                if (serverInfo) {
                    if (serverInfo.browser) frag.push('<dt>Browser (parsed)</dt><dd>' + escapeHtml(serverInfo.browser + (serverInfo.browser_version ? ' ' + serverInfo.browser_version : '')) + '</dd>');
                    if (serverInfo.os) frag.push('<dt>OS (parsed)</dt><dd>' + escapeHtml(serverInfo.os + (serverInfo.os_version ? ' ' + serverInfo.os_version : '')) + '</dd>');
                }
                if (clientInfo) {
                    if (clientInfo.browser_brands) frag.push('<dt>Browser (Client Hints)</dt><dd>' + escapeHtml(clientInfo.browser_brands) + '</dd>');
                    if (clientInfo.ua_full_version) frag.push('<dt>Browser full version</dt><dd>' + escapeHtml(clientInfo.ua_full_version) + '</dd>');
                    if (clientInfo.platform) frag.push('<dt>Platform</dt><dd>' + escapeHtml(clientInfo.platform) + '</dd>');
                    if (clientInfo.platform_version) frag.push('<dt>Platform version</dt><dd>' + escapeHtml(clientInfo.platform_version) + '</dd>');
                    if (clientInfo.mobile !== undefined) frag.push('<dt>Mobile</dt><dd>' + (clientInfo.mobile ? 'Yes' : 'No') + '</dd>');
                    if (clientInfo.architecture) frag.push('<dt>Architecture</dt><dd>' + escapeHtml(clientInfo.architecture) + '</dd>');
                    if (clientInfo.screen) frag.push('<dt>Screen</dt><dd>' + escapeHtml(clientInfo.screen) + '</dd>');
                    if (clientInfo.timezone) frag.push('<dt>Timezone</dt><dd>' + escapeHtml(clientInfo.timezone) + '</dd>');
                    if (clientInfo.languages) frag.push('<dt>Languages</dt><dd>' + escapeHtml(clientInfo.languages) + '</dd>');
                    if (clientInfo.plugins) frag.push('<dt>Plugins</dt><dd>' + escapeHtml(clientInfo.plugins) + '</dd>');
                    if (clientInfo.hardware_concurrency) frag.push('<dt>CPU cores</dt><dd>' + escapeHtml(String(clientInfo.hardware_concurrency)) + '</dd>');
                    if (clientInfo.device_memory_gb) frag.push('<dt>Device memory</dt><dd>' + escapeHtml(clientInfo.device_memory_gb + ' GB') + '</dd>');
                }
                if (serverInfo && serverInfo.user_agent) frag.push('<dt>User-Agent</dt><dd style="font-size:11px;word-break:break-all;">' + escapeHtml(serverInfo.user_agent) + '</dd>');
                frag.push('</dl>');
                const el = document.getElementById('deviceInfo');
                el.innerHTML = frag.join('');
                el.classList.remove('hidden');
            }
            
            function escapeHtml(s) {
                const div = document.createElement('div');
                div.textContent = s;
                return div.innerHTML;
            }
            
            function showSpinner() {
                document.getElementById('spinner').classList.remove('hidden');
            }
            
            function hideSpinner() {
                document.getElementById('spinner').classList.add('hidden');
            }

            function stopPolling() {
                if (pollTimer) {
                    clearInterval(pollTimer);
                    pollTimer = null;
                }
            }

            function pickDeniedSnark(snarkIndex) {
                if (typeof snarkIndex === 'number' && snarkIndex >= 0 && snarkIndex < DENY_SNARKS.length) {
                    return DENY_SNARKS[snarkIndex];
                }
                return DENY_SNARKS[Math.floor(Math.random() * DENY_SNARKS.length)];
            }

            function showDenied(serverMsg, canRetry, snarkIndex) {
                if (canRetry === undefined) canRetry = true;
                stopPolling();
                const flow = document.getElementById('pairingFlow');
                const deniedPanel = document.getElementById('deniedPanel');
                if (flow) flow.classList.add('hidden');
                if (!deniedPanel) return;
                deniedPanel.classList.remove('denied-permanent');
                const hero = deniedPanel.querySelector('.denied-hero');
                if (hero) hero.textContent = 'Access denied';
                const hint = document.getElementById('deniedHint');
                if (hint) {
                    hint.textContent = 'If that was a mistake, you get exactly one more shot at requesting access. Use it wisely.';
                }
                const retryBtn = document.getElementById('deniedRetry');
                if (retryBtn) {
                    retryBtn.classList.toggle('hidden', !canRetry);
                    retryBtn.hidden = !canRetry;
                }
                const snarkEl = document.getElementById('deniedSnark');
                const customEl = document.getElementById('deniedCustom');
                if (snarkEl && DENY_SNARKS.length) {
                    snarkEl.textContent = pickDeniedSnark(snarkIndex);
                }
                if (customEl) {
                    const t = serverMsg && String(serverMsg).trim();
                    if (t) {
                        customEl.textContent = t;
                        customEl.classList.remove('hidden');
                    } else {
                        customEl.textContent = '';
                        customEl.classList.add('hidden');
                    }
                }
                deniedPanel.classList.remove('hidden');
                hideSpinner();
                const gl = document.getElementById('pairGateLoading');
                if (gl) gl.classList.add('hidden');
            }

            function showPermanentDenied(serverMsg, publicKeyForHistory, snarkIndex) {
                stopPolling();
                const flow = document.getElementById('pairingFlow');
                const deniedPanel = document.getElementById('deniedPanel');
                if (flow) flow.classList.add('hidden');
                if (!deniedPanel) return;
                deniedPanel.classList.add('denied-permanent');
                const hero = deniedPanel.querySelector('.denied-hero');
                if (hero) hero.textContent = 'Access permanently denied';
                const hint = document.getElementById('deniedHint');
                if (hint) {
                    hint.textContent = 'You already burned your retry. This device key is done pairing here — clear site data for this origin if you need a fresh identity, or grovel to your admin.';
                }
                const retryBtn = document.getElementById('deniedRetry');
                if (retryBtn) {
                    retryBtn.classList.add('hidden');
                    retryBtn.hidden = true;
                }
                if (publicKeyForHistory && typeof history.replaceState === 'function') {
                    try {
                        const u = new URL(window.location.href);
                        u.searchParams.set('public_key', publicKeyForHistory);
                        history.replaceState(null, '', u.pathname + u.search + u.hash);
                    } catch (e) {}
                }
                const snarkEl = document.getElementById('deniedSnark');
                const customEl = document.getElementById('deniedCustom');
                if (snarkEl && DENY_SNARKS.length) {
                    snarkEl.textContent = pickDeniedSnark(snarkIndex);
                }
                if (customEl) {
                    const t = serverMsg && String(serverMsg).trim();
                    if (t) {
                        customEl.textContent = t;
                        customEl.classList.remove('hidden');
                    } else {
                        customEl.textContent = '';
                        customEl.classList.add('hidden');
                    }
                }
                deniedPanel.classList.remove('hidden');
                hideSpinner();
                const gl = document.getElementById('pairGateLoading');
                if (gl) gl.classList.add('hidden');
            }

            function resetDeniedToPairing() {
                const flow = document.getElementById('pairingFlow');
                const deniedPanel = document.getElementById('deniedPanel');
                const panel = document.getElementById('requestPanel');
                if (deniedPanel) {
                    deniedPanel.classList.add('hidden');
                    deniedPanel.classList.remove('denied-permanent');
                }
                if (flow) flow.classList.remove('hidden');
                ['status', 'deviceId', 'instructions', 'deviceInfo', 'spinner'].forEach(function(id) {
                    const el = document.getElementById(id);
                    if (el) el.classList.add('hidden');
                });
                if (panel) panel.classList.remove('hidden');
                const retryBtn = document.getElementById('deniedRetry');
                if (retryBtn) {
                    retryBtn.classList.remove('hidden');
                    retryBtn.hidden = false;
                }
            }
            
            /** Pairing API always returns JSON from this app; proxies/errors may not — handle both. */
            async function parsePairingResponse(response) {
                const text = await response.text();
                let data = null;
                if (text) {
                    try {
                        data = JSON.parse(text);
                    } catch (e) {
                        const snippet = text.replace(/\s+/g, ' ').trim().slice(0, 180);
                        throw new Error('Server did not return JSON (HTTP ' + response.status + '). ' + (snippet || 'Empty body'));
                    }
                }
                if (!response.ok) {
                    const msg = (data && data.error) ? data.error : ('Request failed (HTTP ' + response.status + ')');
                    const err = new Error(msg);
                    if (data && data.code) err.code = data.code;
                    err.httpStatus = response.status;
                    throw err;
                }
                return data;
            }
            
            async function registerDevice() {
                const keypair = await getKeyPair();
                const timestamp = Date.now().toString();
                const clientInfo = await getClientDeviceInfo();
                const nameEl = document.getElementById('displayName');
                if (nameEl && nameEl.value) {
                    clientInfo.display_name = nameEl.value;
                }

                const panel = document.getElementById('requestPanel');
                if (panel) panel.classList.add('hidden');
                
                showSpinner();
                
                try {
                    // For now, we'll send the public key and let the server handle it
                    // In a full implementation, you'd sign the timestamp here
                    const response = await fetch(API_PATH, {
                        method: 'POST',
                        credentials: 'include',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            action: 'register',
                            public_key: keypair.publicKey,
                            device_id: '',
                            signature: '', // Would be signed timestamp
                            timestamp: timestamp,
                            client_info: clientInfo
                        })
                    });
                    
                    const data = await parsePairingResponse(response);
                    const resolvedDeviceID = data.device_id || 'unknown-device-id';
                    showDeviceID(resolvedDeviceID);
                    
                    if (data.status === 'authorized') {
                        persistSessionSecret(data);
                        if (notifyVpnlessAndroidIfEmbedded()) {
                            return;
                        }
                        showStatus('✅ Device authorized! Redirecting...', 'authorized');
                        setTimeout(() => {
                            window.location.href = '/';
                        }, 2000);
                    } else if (data.status === 'permanently_denied') {
                        showPermanentDenied(data.deny_message, keypair.publicKey, data.snark_index);
                    } else if (data.status === 'denied') {
                        showDenied(data.deny_message, data.can_retry !== false, data.snark_index);
                    } else {
                        showStatus('⏳ Waiting for approval...', 'pending');
                        showInstructions('Device ID: ' + resolvedDeviceID + ' — approve it in admin when you get there.');
                        startPolling(keypair.publicKey, resolvedDeviceID);
                    }
                } catch (error) {
                    if (error.code === 'pairing_exhausted') {
                        showPermanentDenied(error.message || '', keypair.publicKey);
                    } else {
                        showStatus('❌ Error: ' + error.message, 'error');
                        if (panel) panel.classList.remove('hidden');
                    }
                } finally {
                    hideSpinner();
                }
            }
            
            function startPolling(publicKey, deviceID) {
                stopPolling();
                pollTimer = setInterval(async () => {
                    try {
                        const response = await fetch(API_PATH, {
                            method: 'POST',
                            credentials: 'include',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                action: 'check',
                                public_key: publicKey,
                                device_id: deviceID,
                                signature: '',
                                timestamp: Date.now().toString()
                            })
                        });
                        
                        const data = await parsePairingResponse(response);
                        
                        if (data && data.status === 'authorized') {
                            stopPolling();
                            persistSessionSecret(data);
                            if (notifyVpnlessAndroidIfEmbedded()) {
                                return;
                            }
                            showStatus('✅ Device authorized! Redirecting...', 'authorized');
                            setTimeout(() => {
                                window.location.href = '/';
                            }, 2000);
                        } else if (data && data.status === 'permanently_denied') {
                            showPermanentDenied(data.deny_message, publicKey, data.snark_index);
                        } else if (data && data.status === 'denied') {
                            showDenied(data.deny_message, data.can_retry !== false, data.snark_index);
                        }
                    } catch (error) {
                        console.error('Polling error:', error);
                    }
                }, 3000); // Poll every 3 seconds
            }
            
            function hidePairGateLoading() {
                const g = document.getElementById('pairGateLoading');
                if (g) g.classList.add('hidden');
            }

            initTheme();
            (async function pairingBootstrap() {
                let raw = null;
                try { raw = localStorage.getItem(STORAGE_KEY); } catch (e) {}
                const gate = document.getElementById('pairGateLoading');
                const flow = document.getElementById('pairingFlow');
                let consumed = false;
                if (raw) {
                    if (gate) gate.classList.remove('hidden');
                    if (flow) flow.classList.add('hidden');
                    try {
                        const kp = JSON.parse(raw);
                        if (kp && kp.publicKey) {
                            const response = await fetch(API_PATH, {
                                method: 'POST',
                                credentials: 'include',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                    action: 'check',
                                    public_key: kp.publicKey,
                                    device_id: '',
                                    signature: '',
                                    timestamp: Date.now().toString()
                                })
                            });
                            const data = await parsePairingResponse(response);
                            if (data.status === 'permanently_denied') {
                                showPermanentDenied(data.deny_message, kp.publicKey, data.snark_index);
                                consumed = true;
                            } else if (data.status === 'authorized') {
                                persistSessionSecret(data);
                                if (notifyVpnlessAndroidIfEmbedded()) {
                                    hidePairGateLoading();
                                    return;
                                }
                                hidePairGateLoading();
                                window.location.href = '/';
                                return;
                            } else if (data.status === 'denied') {
                                showDenied(data.deny_message, data.can_retry !== false, data.snark_index);
                                consumed = true;
                            }
                        }
                    } catch (e) {
                        console.warn('Pairing gate:', e);
                    }
                    hidePairGateLoading();
                    if (!consumed && flow) flow.classList.remove('hidden');
                } else {
                    hidePairGateLoading();
                }
                const btn = document.getElementById('requestBtn');
                if (btn) btn.addEventListener('click', function() { registerDevice(); });
                const nameInput = document.getElementById('displayName');
                if (nameInput) nameInput.addEventListener('keydown', function(ev) {
                    if (ev.key === 'Enter') {
                        ev.preventDefault();
                        registerDevice();
                    }
                });
                const deniedRetry = document.getElementById('deniedRetry');
                if (deniedRetry) deniedRetry.addEventListener('click', function() { resetDeniedToPairing(); });
                if (typeof VPNLessFetchAuth !== 'undefined') {
                    VPNLessFetchAuth.install({ sameOriginOnly: true });
                }
            })();
        })();
    </script>
</body>
</html>`

// pairingBannedPageHTML is served with HTTP 403 when GET pairing is requested with a permanently blocked public_key.
const pairingBannedPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pairing closed</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; margin: 0; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .card { background: rgba(255,255,255,.96); color: #20242a; max-width: 520px; padding: 28px 24px; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,.25); }
        h1 { margin: 0 0 12px; font-size: 1.35rem; }
        p { margin: 0; line-height: 1.55; color: #444; font-size: 15px; }
    </style>
</head>
<body>
<div class="card">
    <h1>Pairing is closed for this device</h1>
    <p>This browser’s VPNLess device key burned through its chances. Clear site data for this site (or use another profile) if you legitimately need a new identity—or contact whoever runs this place.</p>
</div>
</body>
</html>`

const approvalDashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPNLess Admin</title>
    <style>
        :root {
            --bg: #f5f5f5;
            --surface: #ffffff;
            --text: #20242a;
            --muted: #555;
            --border: #dde2e8;
            --input-bg: #ffffff;
            --input-text: #20242a;
            --input-border: #cfd6de;
            --input-placeholder: #7d8694;
        }
        :root[data-theme="dark"] {
            --bg: #12161c;
            --surface: #1a2029;
            --text: #e6e9ee;
            --muted: #a5adba;
            --border: #2c3644;
            --input-bg: #0f141b;
            --input-text: #e6e9ee;
            --input-border: #3b4556;
            --input-placeholder: #95a0b2;
        }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background:var(--bg); color:var(--text); padding:20px; }
        .container { max-width:1000px; margin:0 auto; background:var(--surface); border-radius:8px; padding:24px; box-shadow:0 2px 10px rgba(0,0,0,.1); position:relative; }
        h1 { margin:0 0 16px; }
        .hidden { display:none; }
        .panel { border:1px solid var(--border); border-radius:8px; padding:14px; margin:12px 0; background:color-mix(in oklab, var(--surface) 80%, #f8f9fa); }
        .warn { border-left:4px solid #f39c12; }
        .row { margin:8px 0; }
        label { display:block; font-size:13px; margin-bottom:4px; }
        input { box-sizing:border-box; width:100%; max-width:420px; padding:8px 10px; border:1px solid var(--input-border); border-radius:6px; background:var(--input-bg); color:var(--input-text); }
        input::placeholder { color: var(--input-placeholder); }
        input.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
        button { border:none; border-radius:6px; padding:9px 14px; cursor:pointer; }
        .primary { background:#007bff; color:#fff; }
        .ok { background:#28a745; color:#fff; }
        .secondary { background:#6c757d; color:#fff; }
        .danger { background:#dc3545; color:#fff; }
        .sp { margin-left:8px; }
        .msg { margin-top:8px; font-size:13px; color:var(--muted); }
        .pending-list { margin-top:16px; }
        .device { border:1px solid var(--border); border-radius:8px; padding:14px; margin-bottom:10px; background:color-mix(in oklab, var(--surface) 85%, #fafafa); }
        .device-id { font-family:'Courier New', monospace; font-weight:700; margin-bottom:6px; }
        .authorized-device-details summary { cursor:pointer; font-weight:600; user-select:none; color:var(--text); list-style: none; }
        .authorized-device-details summary::-webkit-details-marker { display: none; }
        .authorized-device-details summary::before { content: '▸ '; display: inline-block; transition: transform 0.15s; }
        .authorized-device-details[open] summary::before { transform: rotate(90deg); }
        .authorized-name-edit-row { display:none; flex-wrap:wrap; gap:8px; align-items:center; }
        .device.authorized-name-is-editing .authorized-name-edit-row { display:flex; }
        .device.authorized-name-is-editing .authorized-name-edit-btn { display:none; }
        .auth-legend { font-size:13px; line-height:1.5; margin:0 0 12px; padding:10px 12px; border-radius:8px; border:1px solid var(--border); background:color-mix(in oklab, var(--surface) 88%, var(--bg)); }
        .auth-badge-row { display:flex; flex-wrap:wrap; gap:8px; margin:8px 0 0; align-items:center; font-size:12px; }
        .auth-badge-strong { display:inline-flex; align-items:center; gap:4px; padding:4px 10px; border-radius:999px; background:color-mix(in oklab, #28a745 22%, var(--surface)); color:var(--text); border:1px solid color-mix(in oklab, #28a745 45%, var(--border)); font-weight:600; }
        .auth-badge-weak { display:inline-flex; align-items:center; gap:4px; padding:4px 10px; border-radius:999px; background:color-mix(in oklab, #e8a938 20%, var(--surface)); color:var(--text); border:1px solid color-mix(in oklab, #e8a938 50%, var(--border)); font-weight:600; }
        .auth-badge-muted { display:inline-flex; align-items:center; gap:4px; padding:4px 10px; border-radius:999px; background:color-mix(in oklab, var(--muted) 12%, var(--surface)); color:var(--muted); border:1px solid var(--border); }
        .device.vpnless-strong { border-left:4px solid #28a745; padding-left:12px; margin-left:-2px; }
        .device.vpnless-weak { border-left:4px solid #e8a938; padding-left:12px; margin-left:-2px; }
        .device.vpnless-unknown { border-left:4px solid #6c757d; padding-left:12px; margin-left:-2px; }
        :root[data-theme="dark"] .auth-badge-strong { background:color-mix(in oklab, #28a745 18%, var(--surface)); border-color:color-mix(in oklab, #28a745 35%, var(--border)); }
        :root[data-theme="dark"] .auth-badge-weak { background:color-mix(in oklab, #e8a938 14%, var(--surface)); border-color:color-mix(in oklab, #e8a938 30%, var(--border)); }
        .empty { text-align:center; color:var(--muted); padding:38px 12px; }
        .modal { position:fixed; inset:0; background:rgba(0,0,0,.5); display:flex; align-items:center; justify-content:center; }
        .modal.hidden { display:none; }
        .modal-card { background:var(--surface); padding:18px; border-radius:8px; width:360px; max-width:95vw; text-align:center; }
        .deny-modal-inner { background:var(--surface); padding:20px 22px; border-radius:10px; width:min(540px,94vw); max-height:90vh; overflow-y:auto; text-align:left; box-shadow:0 8px 32px rgba(0,0,0,.2); }
        .deny-modal-inner h3 { margin:0 0 6px; font-size:1.15rem; }
        .deny-snark-list { list-style:none; margin:0 0 14px; padding:0; max-height:min(260px,40vh); overflow-y:auto; border:1px solid var(--border); border-radius:8px; background:color-mix(in oklab, var(--surface) 92%, var(--bg)); }
        .deny-snark-list li { padding:8px 12px; font-size:13px; line-height:1.45; border-bottom:1px solid var(--border); color:var(--text); cursor:pointer; outline:none; }
        .deny-snark-list li:last-child { border-bottom:none; }
        .deny-snark-list li:not(.snark-picked):hover, .deny-snark-list li:not(.snark-picked):focus-visible { background:color-mix(in oklab, var(--surface) 70%, #cfe2ff); }
        :root[data-theme="dark"] .deny-snark-list li:not(.snark-picked):hover, :root[data-theme="dark"] .deny-snark-list li:not(.snark-picked):focus-visible { background:color-mix(in oklab, var(--surface) 75%, #1e3a5f); }
        .deny-snark-list li.snark-picked { background:color-mix(in oklab, #fff3cd 55%, var(--surface)); border-left:4px solid #e8a938; padding-left:8px; font-weight:600; }
        :root[data-theme="dark"] .deny-snark-list li.snark-picked { background:color-mix(in oklab, #664d03 35%, var(--surface)); border-left-color:#f0c14d; }
        .deny-modal-inner textarea { width:100%; max-width:100%; box-sizing:border-box; padding:10px 12px; border:1px solid var(--input-border); border-radius:6px; background:var(--input-bg); color:var(--input-text); font-family:inherit; font-size:14px; line-height:1.45; resize:vertical; min-height:72px; }
        .deny-modal-inner textarea::placeholder { color:var(--input-placeholder); }
        .deny-modal-actions { margin-top:16px; display:flex; flex-wrap:wrap; gap:8px; justify-content:flex-end; }
        .theme-toggle { border:1px solid var(--border); background:transparent; color:var(--text); border-radius:6px; padding:6px 10px; cursor:pointer; font-size:12px; }
        .admin-top-actions { position:absolute; right:16px; top:16px; display:flex; gap:8px; align-items:center; }
        .brand { display:flex; align-items:center; gap:10px; margin:0 0 16px; }
        .brand-logo { width:36px; height:36px; object-fit:contain; }
        .brand-title { margin:0; font-size:28px; line-height:1.1; }
        .admin-tabs { display:flex; gap:6px; flex-wrap:wrap; margin:0 0 16px; border-bottom:1px solid var(--border); padding-bottom:10px; align-items:flex-end; }
        .admin-tab { padding:8px 14px; border-radius:8px 8px 0 0; background:transparent; border:1px solid transparent; color:var(--text); cursor:pointer; font-size:14px; }
        .admin-tab.active { background:color-mix(in oklab, var(--surface) 88%, var(--bg)); border-color:var(--border); border-bottom-color:var(--surface); margin-bottom:-1px; font-weight:600; }
        .tab-panel { margin-top:12px; }
        .cert-row { border:1px solid var(--border); border-radius:8px; padding:12px 14px; margin-bottom:10px; background:color-mix(in oklab, var(--surface) 88%, #fafafa); }
        .cert-row.cert-ok { border-left:4px solid #28a745; }
        .cert-row.cert-warn { border-left:4px solid #e8a938; }
        .cert-row.cert-bad { border-left:4px solid #dc3545; }
        .cert-summary { cursor:pointer; font-weight:600; list-style:none; user-select:none; color:var(--text); }
        .cert-summary::-webkit-details-marker { display:none; }
        .cert-summary::before { content:'▸ '; display:inline-block; transition:transform 0.15s; }
        details.cert-details[open] > summary.cert-summary::before { transform:rotate(90deg); }
        .cert-meta { font-size:13px; color:var(--muted); margin-top:6px; line-height:1.4; }
        .cert-badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:600; margin-left:8px; vertical-align:middle; }
        .cert-badge.b-ok { background:color-mix(in oklab, #28a745 20%, var(--surface)); color:var(--text); border:1px solid color-mix(in oklab, #28a745 40%, var(--border)); }
        .cert-badge.b-warn { background:color-mix(in oklab, #e8a938 18%, var(--surface)); color:var(--text); border:1px solid color-mix(in oklab, #e8a938 45%, var(--border)); }
        .cert-badge.b-bad { background:color-mix(in oklab, #dc3545 18%, var(--surface)); color:var(--text); border:1px solid color-mix(in oklab, #dc3545 40%, var(--border)); }
        .apps-section-title { font-size:1.05rem; font-weight:700; margin:20px 0 10px; padding-bottom:6px; border-bottom:1px solid var(--border); }
        .apps-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(200px,1fr)); gap:14px; margin-bottom:8px; }
        .app-card { display:flex; flex-direction:column; align-items:flex-start; gap:8px; padding:14px; border:1px solid var(--border); border-radius:10px; background:color-mix(in oklab, var(--surface) 90%, var(--bg)); text-decoration:none; color:inherit; transition:background .15s, border-color .15s; }
        a.app-card:hover { background:color-mix(in oklab, var(--surface) 78%, #cfe2ff); border-color:color-mix(in oklab, #0d6efd 35%, var(--border)); }
        :root[data-theme="dark"] a.app-card:hover { background:color-mix(in oklab, var(--surface) 82%, #1e3a5f); }
        .app-card-icon { width:44px; height:44px; object-fit:contain; border-radius:8px; background:color-mix(in oklab, var(--surface) 70%, var(--bg)); }
        .app-card-name { font-weight:600; font-size:15px; line-height:1.25; }
        .app-card-desc { font-size:12px; color:var(--muted); line-height:1.35; }
        .app-card-meta { font-size:11px; color:var(--muted); font-family:ui-monospace,monospace; }
        .device-filter-bar { display:flex; flex-wrap:wrap; gap:8px; margin:0 0 14px; align-items:center; }
        .device-filter-btn { border:1px solid var(--border); border-radius:8px; padding:7px 12px; cursor:pointer; font-size:13px; background:color-mix(in oklab, var(--surface) 88%, var(--bg)); color:var(--text); }
        .device-filter-btn.active { background:color-mix(in oklab, #0d6efd 22%, var(--surface)); border-color:color-mix(in oklab, #0d6efd 45%, var(--border)); font-weight:600; }
        :root[data-theme="dark"] .device-filter-btn.active { background:color-mix(in oklab, #0d6efd 18%, var(--surface)); border-color:color-mix(in oklab, #0d6efd 35%, var(--border)); }
        .overview-section-title { font-size:1.05rem; font-weight:700; margin:18px 0 8px; }
        .activity-table-wrap { overflow-x:auto; border:1px solid var(--border); border-radius:8px; }
        table.activity-table { width:100%; border-collapse:collapse; font-size:13px; }
        table.activity-table th, table.activity-table td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); }
        table.activity-table th { color:var(--muted); font-weight:600; }
        .activity-status { font-weight:600; }
        .activity-status.pending { color:#e8a938; }
        .activity-status.authorized { color:#28a745; }
        .activity-status.denied { color:#dc3545; }
        .activity-status.threat { color:#6f42c1; }
        .torture-bot-card { border:1px solid var(--border); border-radius:10px; margin-bottom:14px; padding:12px 14px; background:color-mix(in oklab, var(--surface) 90%, var(--bg)); cursor:pointer; transition:border-color .15s, background .15s; }
        .torture-bot-card:hover { border-color:color-mix(in oklab, #6f42c1 35%, var(--border)); background:color-mix(in oklab, var(--surface) 82%, #f3e8ff); }
        :root[data-theme="dark"] .torture-bot-card:hover { background:color-mix(in oklab, var(--surface) 88%, #2d1f3d); }
        .torture-bot-head { font-size:14px; font-weight:600; margin:0 0 6px; }
        .torture-bot-meta { font-size:12px; color:var(--muted); margin-bottom:8px; line-height:1.4; }
        .torture-preview { font-family:ui-monospace,monospace; font-size:12px; line-height:1.45; color:var(--text); white-space:pre-wrap; word-break:break-word; border-left:3px solid color-mix(in oklab, #6f42c1 50%, var(--border)); padding-left:10px; margin:0; }
        .torture-overlay { position:fixed; inset:0; z-index:90; background:rgba(0,0,0,.5); display:flex; align-items:center; justify-content:center; padding:14px; box-sizing:border-box; }
        .torture-overlay.hidden { display:none; }
        .torture-overlay-inner { width:min(960px,100%); max-height:min(92vh,900px); display:flex; flex-direction:column; background:var(--surface); border-radius:12px; border:1px solid var(--border); box-shadow:0 16px 48px rgba(0,0,0,.25); overflow:hidden; }
        .torture-overlay-bar { display:flex; justify-content:space-between; align-items:center; gap:12px; padding:12px 16px; border-bottom:1px solid var(--border); flex-shrink:0; }
        .torture-overlay-bar h3 { margin:0; font-size:1.12rem; }
        .torture-overlay-body { padding:12px 16px 16px; flex:1; min-height:0; display:flex; flex-direction:column; }
        .torture-transcript-overlay { flex:1; min-height:min(520px,55vh); max-height:min(70vh,640px); overflow:auto; border:1px solid var(--border); border-radius:8px; padding:10px 12px; background:var(--input-bg); font-family:ui-monospace,monospace; font-size:12px; line-height:1.5; }
        .torture-line-in { color:color-mix(in oklab, #0d6efd 58%, var(--text)); margin-bottom:4px; white-space:pre-wrap; word-break:break-word; }
        .torture-line-out { color:color-mix(in oklab, #b02a37 52%, var(--text)); margin-bottom:4px; white-space:pre-wrap; word-break:break-word; }
        :root[data-theme="dark"] .torture-line-in { color:#8ec5ff; }
        :root[data-theme="dark"] .torture-line-out { color:#ff9a9a; }
        .threat-action-btn-inner { display:inline-flex; align-items:center; gap:6px; vertical-align:middle; }
        .threat-action-icon { flex-shrink:0; display:block; }
        /* Mobile: one full-bleed surface — drop the outer body frame + inner card “double box”. */
        @media (max-width: 640px) {
            body {
                padding: 12px 14px 20px;
                background: var(--surface);
            }
            .container {
                max-width: none;
                margin: 0;
                padding: 0;
                background: transparent;
                box-shadow: none;
                border-radius: 0;
            }
            .admin-top-actions {
                right: 0;
                top: 0;
                gap: 6px;
            }
        }
    </style>
</head>
<body>
<div class="container">
    <div class="brand">
        <img class="brand-logo" src="/vpnless-icon.svg" alt="VPNLess" />
        <h1 class="brand-title">VPNLess Admin</h1>
    </div>

    <div id="loginPanel" class="panel" autocomplete="off">
        <div class="row"><label>Username</label><input id="loginUser" autocomplete="off" autocapitalize="off" spellcheck="false" /></div>
        <div class="row"><label>Password</label><input id="loginPass" type="password" autocomplete="new-password" /></div>
        <div class="row hidden" id="loginOtpRow"><label>OTP code</label><input id="loginOtp" inputmode="numeric" maxlength="6" class="mono" autocomplete="off" /></div>
        <button class="primary" onclick="login()">Sign in</button>
        <div id="loginMsg" class="msg"></div>
    </div>

    <div id="mainPanel" class="hidden">
        <!-- Lucide-derived icons (ISC): see adminui-icons/NOTICE — inline sprite so stroke uses currentColor (theme). -->
        <svg xmlns="http://www.w3.org/2000/svg" style="position:absolute;width:0;height:0;overflow:hidden" aria-hidden="true">
            <defs>
                <symbol id="vpl-ic-tarpit" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 13a6 6 0 1 0 12 0 4 4 0 1 0-8 0 2 2 0 0 0 4 0"/><circle cx="10" cy="13" r="8"/><path d="M2 21h12c4.4 0 8-3.6 8-8V7a2 2 0 1 0-4 0v6"/><path d="M18 3 19.1 5.2"/><path d="M22 3 20.9 5.2"/></symbol>
                <symbol id="vpl-ic-honeypot" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2v6a2 2 0 0 0 .245.96l5.51 10.08A2 2 0 0 1 18 22H6a2 2 0 0 1-1.755-2.96l5.51-10.08A2 2 0 0 0 10 8V2"/><path d="M6.453 15h11.094"/><path d="M8.5 2h7"/></symbol>
                <symbol id="vpl-ic-slop" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 16c5 0 7-8 12-8a4 4 0 0 1 0 8c-5 0-7-8-12-8a4 4 0 1 0 0 8"/></symbol>
                <symbol id="vpl-ic-blacklist" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M4.929 4.929 19.07 19.071"/></symbol>
                <symbol id="vpl-ic-clear" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></symbol>
            </defs>
        </svg>
        <div class="admin-top-actions">
            <button class="theme-toggle" type="button" onclick="adminPollTick();">Refresh</button>
            <button class="theme-toggle" type="button" onclick="logout()">Logout</button>
            <button id="themeToggle" class="theme-toggle" type="button">Theme</button>
        </div>
        <div id="otpSetup" class="panel warn hidden">
            <strong>Set up TOTP for admin login</strong>
            <div class="row">
                <label>OTP secret</label>
                <input id="otpSecret" class="mono" type="password" readonly />
                <button class="secondary" onclick="copySecret()">Copy</button>
                <button class="secondary sp" onclick="showQR()">Show QR Code</button>
            </div>
            <div class="row">
                <label>Enter current OTP from your authenticator</label>
                <input id="otpVerify" class="mono" inputmode="numeric" maxlength="6" />
            </div>
            <button class="ok" onclick="enableOTP()">Enable OTP</button>
            <div id="otpMsg" class="msg"></div>
        </div>

        <div class="admin-tabs" role="tablist" aria-label="Admin sections">
            <button type="button" class="admin-tab active" id="tabBtnOverview" role="tab" aria-selected="true" aria-controls="tabPanelOverview" onclick="setAdminTab('overview')">Overview</button>
            <button type="button" class="admin-tab" id="tabBtnDevices" role="tab" aria-selected="false" aria-controls="tabPanelDevices" onclick="setAdminTab('devices')">Devices</button>
            <button type="button" class="admin-tab" id="tabBtnThreats" role="tab" aria-selected="false" aria-controls="tabPanelThreats" onclick="setAdminTab('threats')">Threat Monitor</button>
            <button type="button" class="admin-tab" id="tabBtnTorture" role="tab" aria-selected="false" aria-controls="tabPanelTorture" onclick="setAdminTab('torture')">Torture Chamber</button>
            <button type="button" class="admin-tab" id="tabBtnApps" role="tab" aria-selected="false" aria-controls="tabPanelApps" onclick="setAdminTab('apps')">Apps</button>
            <button type="button" class="admin-tab" id="tabBtnCerts" role="tab" aria-selected="false" aria-controls="tabPanelCerts" onclick="setAdminTab('certificates')">Certificates</button>
        </div>

        <p class="msg" id="adminPollHint" style="margin-top:4px;">This tab refreshes on a short poll timer while the dashboard is visible (slower when the browser tab is in the background).</p>

        <div id="tabPanelOverview" class="tab-panel" role="tabpanel" aria-labelledby="tabBtnOverview">
            <p class="msg" style="margin-top:0;">At-a-glance: pending devices first, Docker apps whose container was created in the last 24h, and any certificate that is not <strong>ok</strong>.</p>
            <div id="overviewWarning" class="msg warn panel hidden" style="margin:8px 0;"></div>
            <h4 class="overview-section-title">Pending approval</h4>
            <div id="overviewPending" class="pending-list"></div>
            <h4 class="overview-section-title">New apps (container age &lt; 24h)</h4>
            <div id="overviewNewApps" class="pending-list"></div>
            <h4 class="overview-section-title">Certificates needing attention</h4>
            <div id="overviewCerts" class="pending-list"></div>
            <h4 class="overview-section-title">Recent threat monitor events</h4>
            <div id="overviewThreats" class="pending-list"></div>
        </div>

        <div id="tabPanelDevices" class="tab-panel hidden" role="tabpanel" aria-labelledby="tabBtnDevices">
            <p class="auth-legend msg"><strong>Devices tab</strong> is the same data as <code>vpnless list</code> (pending / authorized / denied / activity). <strong>Pending</strong> rows always reflect the pairing flow: display name + client info from the pairing page or embedded WebView, for <em>every</em> client type. After approval, traffic may authenticate via either path: <strong>session proof</strong> headers (HMAC from the paired secret — e.g. <code>VPNLessFetchAuth.install()</code>, forked apps) or the HTTP-only device <strong>cookie</strong> (replayable until revoked). Both are valid; badges on authorized cards show which signal was seen most recently.</p>
            <div class="device-filter-bar" role="tablist" aria-label="Device list filter">
                <button type="button" class="device-filter-btn active" data-filter="all" onclick="setDeviceFilter('all')">All</button>
                <button type="button" class="device-filter-btn" data-filter="pending" onclick="setDeviceFilter('pending')">Pending</button>
                <button type="button" class="device-filter-btn" data-filter="authorized" onclick="setDeviceFilter('authorized')">Authorized</button>
                <button type="button" class="device-filter-btn" data-filter="denied" onclick="setDeviceFilter('denied')">Denied</button>
            </div>
            <div id="deviceFilterList" class="pending-list"></div>
        </div>

        <div id="tabPanelThreats" class="tab-panel hidden" role="tabpanel" aria-labelledby="tabBtnThreats">
            <p class="msg" style="margin-top:0;">Tarpit/honeypot/<strong>Endless slop</strong>/blacklist modes are stored in SQLite (same DB as devices), so they apply to <strong>all</strong> Caddy workers. CLI: <code>vpnless list threats</code>. Unblock: <code>vpnless clear-threat &lt;ip&gt;</code> or the row button. For <strong>blacklist</strong>, <em>last hit</em> advances when that IP fails vpnless auth on a <em>protected</em> route. After <strong>20</strong> failed-auth strikes in <code>default</code> mode, an IP is auto-blacklisted for 30 minutes. If bans look wrong, check <code>trusted_proxy</code> in Caddy — without it, <code>X-Forwarded-For</code> is trusted from anyone who can reach Caddy.</p>
            <div id="threatList" class="msg">Loading threat telemetry...</div>
        </div>

        <div id="tabPanelTorture" class="tab-panel hidden" role="tabpanel" aria-labelledby="tabBtnTorture">
            <p class="msg" style="margin-top:0;"><strong>Tarpit</strong>, <strong>honeypot</strong>, and <strong>endless slop</strong> sessions are logged here (in-memory on this Caddy worker). Each IP shows its <em>latest</em> session; newest pain first. Click a bot to fullscreen the live transcript — still updates while the bot is on the hook.</p>
            <div id="tortureChamberList" class="pending-list">Loading torture chamber…</div>
        </div>

        <div id="tabPanelApps" class="tab-panel hidden" role="tabpanel" aria-labelledby="tabBtnApps">
            <p class="msg" style="margin-top:0;">Apps from <strong>running</strong> containers use Get Homepage–style labels: <code>homepage.name</code>, <code>homepage.href</code>, <code>homepage.group</code>, <code>homepage.icon</code>, <code>homepage.description</code>, plus optional <code>homepage.weight</code> (lower = earlier in the group; default <code>0</code> like Get Homepage). <strong>Groups</strong> are listed A–Z by group name. Icons use <a href="https://github.com/homarr-labs/dashboard-icons" target="_blank" rel="noopener">homarr-labs/dashboard-icons</a> on jsDelivr unless the icon is a full URL.</p>
            <div id="appsWarning" class="msg warn panel hidden" style="margin:8px 0;"></div>
            <div id="appsList" class="pending-list">Loading apps…</div>
        </div>

        <div id="tabPanelCerts" class="tab-panel hidden" role="tabpanel" aria-labelledby="tabBtnCerts">
            <p class="msg" style="margin-top:0;">HTTPS certificates loaded in Caddy for each host matcher found in your HTTP routes. Order: problems first, then soonest expiry. Open a row for ACME challenge hints from the active automation policy (when Caddy exposes it).</p>
            <div id="certWarning" class="msg warn panel hidden" style="margin:8px 0;"></div>
            <div id="certList" class="pending-list">Loading certificates…</div>
        </div>
    </div>
</div>

<div id="tortureOverlay" class="torture-overlay hidden" onclick="closeTortureOverlay(event)" role="dialog" aria-modal="true" aria-labelledby="tortureOverlayTitle">
    <div class="torture-overlay-inner" onclick="event.stopPropagation()">
        <div class="torture-overlay-bar">
            <h3 id="tortureOverlayTitle">Torture feed</h3>
            <button type="button" class="secondary" onclick="closeTortureOverlay()">Close</button>
        </div>
        <div class="torture-overlay-body">
            <p class="msg" style="margin:0 0 10px;line-height:1.45;">Blue lines: their request. Red lines: bytes we trickle back. Refreshes live over SSE until the session ends (or you close this).</p>
            <div id="tortureOverlayTranscript" class="torture-transcript-overlay"></div>
        </div>
    </div>
</div>

<div id="qrModal" class="modal hidden" onclick="hideQR(event)">
    <div class="modal-card" onclick="event.stopPropagation()">
        <h3>Scan this OTP QR code</h3>
        <div id="qrCanvas"></div>
        <button class="secondary" onclick="hideQR()">Close</button>
    </div>
</div>

<div id="denyModal" class="modal hidden" onclick="hideDenyModal(event)">
    <div class="deny-modal-inner" onclick="event.stopPropagation()">
        <h3>Deny device</h3>
        <p class="msg" style="margin:0 0 10px;line-height:1.45;"><strong>Click a line</strong> to choose the canned message their pairing page shows (highlighted row). Optional custom text still appears below it.</p>
        <ul id="denySnarkList" class="deny-snark-list" aria-label="Choose deny message"></ul>
        <label for="denyCustomMsg" style="font-size:13px;font-weight:600;margin-bottom:6px;">Custom message <span style="font-weight:400;color:var(--muted);">(optional)</span></label>
        <textarea id="denyCustomMsg" maxlength="2000" placeholder="Extra text shown on their denied screen, below the snark line"></textarea>
        <div class="deny-modal-actions">
            <button type="button" class="secondary" onclick="hideDenyModal()">Cancel</button>
            <button type="button" class="danger" onclick="submitDeny()">Deny</button>
        </div>
    </div>
</div>

<div id="threatDurationModal" class="modal hidden" onclick="hideThreatDurationModal(event)" role="dialog" aria-modal="true" aria-labelledby="threatDurationTitle">
    <div class="modal-card" onclick="event.stopPropagation()">
        <h3 id="threatDurationTitle">Choose threat duration</h3>
        <p class="msg" style="margin:0 0 12px;line-height:1.45;">
            Presets are in the format the admin uses; <strong>press Enter</strong> in the box to apply.
            Leaving it blank defaults to <strong>1 year</strong>.
        </p>

        <div style="display:flex;flex-wrap:wrap;gap:8px;margin:0 0 12px;">
            <button type="button" class="secondary sp" onclick="setThreatDurationPreset('30m')">30m</button>
            <button type="button" class="secondary sp" onclick="setThreatDurationPreset('3h')">3h</button>
            <button type="button" class="secondary sp" onclick="setThreatDurationPreset('3d')">3d</button>
            <button type="button" class="secondary sp" onclick="setThreatDurationPreset('3w')">3w</button>
            <button type="button" class="secondary sp" onclick="setThreatDurationPreset('3m')">3m</button>
            <button type="button" class="secondary sp" onclick="setThreatDurationPreset('3y')">3y</button>
        </div>

        <label for="threatDurationInput" style="font-size:13px;font-weight:600;margin-bottom:6px;">
            Duration <span style="font-weight:400;color:var(--muted);">(blank = 1y)</span>
        </label>
        <input id="threatDurationInput" class="mono" inputmode="text" placeholder="e.g. 30m, 3d, 1y" style="width:100%;padding:10px 12px;border:1px solid var(--input-border);border-radius:6px;background:var(--input-bg);color:var(--input-text);font-family:inherit;font-size:14px;line-height:1.45;box-sizing:border-box;margin:0 0 14px;"
            onkeydown="if(event.key==='Enter'){event.preventDefault();submitThreatDuration();}" />

        <div class="deny-modal-actions">
            <button type="button" class="secondary" onclick="hideThreatDurationModal()">Cancel</button>
            <button type="button" class="danger" onclick="submitThreatDuration()">Apply</button>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/dayjs@1/dayjs.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/dayjs@1/plugin/relativeTime.js"></script>
<script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.1/build/qrcode.min.js"></script>
<script>
const API_BASE = '__VPNLESS_APPROVAL_BASE__';
const VPNLESS_INITIAL_ADMIN_TAB = __VPNLESS_INITIAL_TAB_JS__;
const THEME_COOKIE = 'vpnless_theme';
/** Same strings as the pairing page — keep in sync when editing snark. */
const DENY_SNARKS = [
    'The admin has spoken. You are not on the list.',
    'Nope. Nada. Nein. Nyet. Take the hint.',
    'This pairing request has left the chat.',
    'Your device ID was read, judged, and found wanting.',
    'Somewhere an admin smiled. It was not for you.',
    'Denied. Don\'t take it personally — or do, we don\'t care.',
    'The velvet rope stayed closed. Try not to trip on it.',
    'Access is a privilege. Today you brought neither cookies nor credentials.',
    'Rejected faster than a NFT pitch at a funeral.',
    'If this were a club, you\'d still be outside in the rain.',
    'The gatekeeper said "lol no" and we\'re obligated to report that faithfully.',
    'Your key is valid; your vibe is not. (Just kidding — the admin clicked Deny.)',
    'Denied with enthusiasm. Consider this a character-building moment.',
    'We ran the numbers. You were not in them.',
];
let denyModalState = null;
let denySnarkListBound = false;
let threatDurationModalState = null;
dayjs.extend(window.dayjs_plugin_relativeTime);
let setupSecret = '';
let setupURI = '';

function escapeHtml(v){const d=document.createElement('div');d.textContent=v==null?'':String(v);return d.innerHTML;}
function escapeAttr(v){return String(v==null?'':v).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;');}
function cookieGet(name){const p=document.cookie.split(';').map(v=>v.trim());for(const v of p){if(v.startsWith(name+'=')) return decodeURIComponent(v.slice(name.length+1));}return '';}
function cookieSet(name,value){document.cookie=name+'='+encodeURIComponent(value)+'; path=/; max-age=157680000; samesite=lax';}
function preferredTheme(){const saved=cookieGet(THEME_COOKIE); if(saved==='light'||saved==='dark') return saved; return window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';}
function applyTheme(theme){document.documentElement.setAttribute('data-theme', theme); const btn=document.getElementById('themeToggle'); if(btn) btn.textContent=theme==='dark'?'Light':'Dark';}
function initTheme(){applyTheme(preferredTheme()); const btn=document.getElementById('themeToggle'); if(!btn) return; btn.addEventListener('click', function(){const current=document.documentElement.getAttribute('data-theme')==='dark'?'dark':'light'; const next=current==='dark'?'light':'dark'; cookieSet(THEME_COOKIE,next); applyTheme(next);});}
function resetLoginFields(){
    const u = document.getElementById('loginUser');
    const p = document.getElementById('loginPass');
    const o = document.getElementById('loginOtp');
    if (u) u.value = '';
    if (p) p.value = '';
    if (o) o.value = '';
}
function enc(v){ return encodeURIComponent(String(v == null ? '' : v)); }

/** Remember which device cards had an open details panel (for admin poll refresh). */
function collectOpenDetailsPublicKeys(wrap) {
    const keys = new Set();
    if (!wrap) return keys;
    wrap.querySelectorAll('.device[data-public-key]').forEach(function(el) {
        const det = el.querySelector('details');
        if (det && det.open) {
            const pk = el.getAttribute('data-public-key');
            if (pk) keys.add(pk);
        }
    });
    return keys;
}
function restoreDetailsOpenByPublicKey(wrap, keys) {
    if (!wrap || !keys || keys.size === 0) return;
    wrap.querySelectorAll('.device[data-public-key]').forEach(function(el) {
        const pk = el.getAttribute('data-public-key');
        if (pk && keys.has(pk)) {
            const det = el.querySelector('details');
            if (det) det.open = true;
        }
    });
}

/** Remember authorized cards where the display-name editor is open (for admin poll refresh). */
function collectAuthorizedNameEditKeys(wrap) {
    const keys = new Set();
    if (!wrap) return keys;
    wrap.querySelectorAll('.device[data-public-key]').forEach(function(el) {
        if (el.classList.contains('authorized-name-is-editing')) {
            const pk = el.getAttribute('data-public-key');
            if (pk) keys.add(pk);
        }
    });
    return keys;
}

function showAuthorizedNameEdit(btn) {
    const card = btn.closest('.device');
    if (card) card.classList.add('authorized-name-is-editing');
}
function cancelAuthorizedNameEdit(btn) {
    const card = btn.closest('.device');
    if (card) card.classList.remove('authorized-name-is-editing');
}

function showMessage(id,msg){document.getElementById(id).textContent=msg;}
function renderNoConnections(){ return '<div class="empty"><h3>No pending devices</h3><p>They appear after someone submits the pairing form (name + automatic device info). That is the same for cookie-only browsers, pages using <code>VPNLessFetchAuth</code>, and embedded clients — approve or deny from the details shown here.</p></div>'; }

async function api(path, opts){
    const o = Object.assign({credentials:'include', cache:'no-store'}, opts||{});
    const method = (o.method || 'GET').toUpperCase();
    let url = API_BASE + path;
    if (method === 'GET') {
        url += (path.indexOf('?') >= 0 ? '&' : '?') + '_=' + Date.now();
    }
    const res = await fetch(url, o);
    const txt = await res.text();
    let data = null; try { data = txt ? JSON.parse(txt) : null; } catch(e) {}
    return {res, data, txt};
}

const ADMIN_POLL_MS_FOCUSED = 2500;
const ADMIN_POLL_MS_BACKGROUND = 12000;
let adminPollTimer = null;
let adminActiveTab = 'overview';
let deviceSubfilter = 'all';
let initialAdminTabApplied = false;
let tortureChamberES = null;

function isAdminDashboardOpen(){
    const p = document.getElementById('mainPanel');
    return p && !p.classList.contains('hidden');
}

function stopAdminPoll(){
    if (adminPollTimer) {
        clearInterval(adminPollTimer);
        adminPollTimer = null;
    }
}

async function adminPollTickAsync(){
    if (!isAdminDashboardOpen()) return;
    const tasks = [];
    if (adminActiveTab === 'overview') tasks.push(loadOverview());
    if (adminActiveTab === 'devices') tasks.push(loadDevicePanel());
    if (adminActiveTab === 'threats') tasks.push(loadThreats());
    if (adminActiveTab === 'apps') tasks.push(loadApps());
    if (adminActiveTab === 'certificates') tasks.push(loadCertificates());
    if (adminActiveTab === 'torture' && (!document.getElementById('tortureOverlay') || document.getElementById('tortureOverlay').classList.contains('hidden'))) {
        tasks.push(loadTortureChamber());
    }
    await Promise.all(tasks);
}

function adminPollTick(){
    adminPollTickAsync().catch(function(e){ console.error('VPNLess admin poll', e); });
}

function pollDelayMs(){
    return document.hidden ? ADMIN_POLL_MS_BACKGROUND : ADMIN_POLL_MS_FOCUSED;
}

function adminPathForTab(name){
    const base = API_BASE.replace(/\/$/, '');
    if (name === 'overview') return base;
    return base + '/' + name;
}

function syncAdminURLForTab(name){
    if (typeof history === 'undefined' || !history.replaceState) return;
    const target = adminPathForTab(name);
    if (window.location.pathname !== target) {
        history.replaceState({ vpnlessAdminTab: name }, '', target);
    }
}

function setAdminTab(name){
    const allowed = ['overview','devices','threats','apps','certificates','torture'];
    if (allowed.indexOf(name) < 0) name = 'overview';
    if (adminActiveTab === 'torture' && name !== 'torture') {
        tortureChamberCloseStream();
        const tox = document.getElementById('tortureOverlay');
        if (tox) tox.classList.add('hidden');
    }
    adminActiveTab = name;
    const ov = document.getElementById('tabPanelOverview');
    const dev = document.getElementById('tabPanelDevices');
    const thr = document.getElementById('tabPanelThreats');
    const apps = document.getElementById('tabPanelApps');
    const cer = document.getElementById('tabPanelCerts');
    const tor = document.getElementById('tabPanelTorture');
    const bOv = document.getElementById('tabBtnOverview');
    const bDev = document.getElementById('tabBtnDevices');
    const bThr = document.getElementById('tabBtnThreats');
    const bApps = document.getElementById('tabBtnApps');
    const bCer = document.getElementById('tabBtnCerts');
    const bTor = document.getElementById('tabBtnTorture');
    const hint = document.getElementById('adminPollHint');
    if (!ov || !dev || !thr || !apps || !cer || !tor || !bOv || !bDev || !bThr || !bApps || !bCer || !bTor) return;

    [ov, dev, thr, apps, cer, tor].forEach(function(p){ p.classList.add('hidden'); });
    [bOv, bDev, bThr, bApps, bCer, bTor].forEach(function(b){
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
    });

    if (name === 'overview') {
        ov.classList.remove('hidden');
        bOv.classList.add('active');
        bOv.setAttribute('aria-selected', 'true');
        if (hint) hint.textContent = 'Overview polls pending, new apps, and certificate status while this tab is visible.';
        loadOverview();
    } else if (name === 'devices') {
        dev.classList.remove('hidden');
        bDev.classList.add('active');
        bDev.setAttribute('aria-selected', 'true');
        if (hint) hint.textContent = 'Device lists respect the filter above; same poll timer (slower in background).';
        loadDevicePanel();
    } else if (name === 'threats') {
        thr.classList.remove('hidden');
        bThr.classList.add('active');
        bThr.setAttribute('aria-selected', 'true');
        if (hint) hint.textContent = 'Threat telemetry uses the same poll timer while this tab is visible.';
        loadThreats();
    } else if (name === 'apps') {
        apps.classList.remove('hidden');
        bApps.classList.add('active');
        bApps.setAttribute('aria-selected', 'true');
        if (hint) hint.textContent = 'Apps refresh from Docker on the same poll timer while this tab stays visible.';
        loadApps();
    } else if (name === 'certificates') {
        cer.classList.remove('hidden');
        bCer.classList.add('active');
        bCer.setAttribute('aria-selected', 'true');
        if (hint) hint.textContent = 'Certificates refresh on the same poll timer while this tab is visible.';
        loadCertificates();
    } else if (name === 'torture') {
        tor.classList.remove('hidden');
        bTor.classList.add('active');
        bTor.setAttribute('aria-selected', 'true');
        if (hint) hint.textContent = 'Torture Chamber refreshes the bot list while visible (pause while a live feed overlay is open). Open a bot for full SSE transcript.';
        loadTortureChamber();
    }
    syncAdminURLForTab(name);
}

function setDeviceFilter(f){
    if (f !== 'all' && f !== 'pending' && f !== 'authorized' && f !== 'denied') f = 'all';
    deviceSubfilter = f;
    document.querySelectorAll('.device-filter-btn').forEach(function(btn){
        const on = btn.getAttribute('data-filter') === f;
        btn.classList.toggle('active', on);
    });
    loadDevicePanel();
}

function refreshDeviceRelatedViews(){
    if (adminActiveTab === 'overview') loadOverview();
    if (adminActiveTab === 'devices') loadDevicePanel();
}

/** Relative time for threat telemetry fields; shared by Overview and Threat Monitor. */
function threatTelemetryRelOrFallback(v, fallback){
    if (!v) return fallback;
    const ts = dayjs(v);
    if (!ts.isValid() || ts.year() < 1971) return fallback;
    return ts.fromNow();
}

/**
 * All five threat actions for one IP (tarpit, honeypot, slop, blacklist, clear).
 * opts.stopPropagation: use inside clickable table rows.
 * opts.buttonClass: e.g. "secondary" or "secondary sp".
 * opts.includeClear: default true.
 * opts.clearButtonLabel: default "Clear / reset" (pass "Remove blacklist" when mode is blacklist).
 * opts.marginTop: default "8px"; use "0" when nested in a grid with gap.
 * opts.flatten: if true, return only buttons (no wrapper) so a parent flex row can include Approve/Deny + threats.
 */
function renderThreatIPActionButtonsHTML(ip, opts){
    opts = opts || {};
    const raw = ip != null ? String(ip).trim() : '';
    if (!raw) return '';
    const sp = opts.stopPropagation ? 'event.stopPropagation();' : '';
    const bc = opts.buttonClass || 'secondary';
    const includeClear = opts.includeClear !== false;
    const clearLbl = opts.clearButtonLabel != null ? String(opts.clearButtonLabel) : 'Clear / reset';
    const marginTop = opts.marginTop != null ? opts.marginTop : '8px';
    const e = enc(raw);
    const threatIconSym = { tarpit:'vpl-ic-tarpit', honeypot:'vpl-ic-honeypot', slop:'vpl-ic-slop', blacklist:'vpl-ic-blacklist', clear:'vpl-ic-clear' };
    function b(action, label){
        const sid = threatIconSym[action];
        const body = sid
            ? '<span class="threat-action-btn-inner"><svg class="threat-action-icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#' + sid + '"/></svg><span>' + escapeHtml(label) + '</span></span>'
            : escapeHtml(label);
        return '<button type="button" class="' + bc + '" onclick="' + sp + 'threatAction(decodeURIComponent(\'' + e + '\'),\'' + action + '\')">' + body + '</button>';
    }
    let inner = b('tarpit', 'Tarpit') + b('honeypot', 'Honeypot') + b('slop', 'Slop') + b('blacklist', 'Blacklist');
    if (includeClear) inner += b('clear', clearLbl);
    if (opts.flatten) return inner;
    return '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:' + marginTop + ';align-items:center;">' + inner + '</div>';
}

// Like renderThreatIPActionButtonsHTML(), but also passes the pending device identity
// so the UI can deny/remove the pending device after applying the threat action.
function renderThreatIPActionButtonsPendingHTML(publicKey, deviceID, ip, opts){
    opts = opts || {};
    const raw = ip != null ? String(ip).trim() : '';
    if (!raw) return '';
    const sp = opts.stopPropagation ? 'event.stopPropagation();' : '';
    const bc = opts.buttonClass || 'secondary';
    const includeClear = opts.includeClear === true; // default false for pending list
    const clearLbl = opts.clearButtonLabel != null ? String(opts.clearButtonLabel) : 'Clear / reset';

    const eIP = enc(raw);
    const ePK = enc(publicKey);
    const eDK = enc(deviceID);
    const threatIconSym = { tarpit:'vpl-ic-tarpit', honeypot:'vpl-ic-honeypot', slop:'vpl-ic-slop', blacklist:'vpl-ic-blacklist', clear:'vpl-ic-clear' };

    function b(action, label){
        const sid = threatIconSym[action];
        const body = sid
            ? '<span class="threat-action-btn-inner"><svg class="threat-action-icon" width="16" height="16" aria-hidden="true" focusable="false"><use href="#' + sid + '"/></svg><span>' + escapeHtml(label) + '</span></span>'
            : escapeHtml(label);
        return '<button type="button" class="' + bc + '" onclick="' + sp + 'threatActionFromPendingDevice(decodeURIComponent(\'' + ePK + '\'),decodeURIComponent(\'' + eDK + '\'),decodeURIComponent(\'' + eIP + '\'),\'' + action + '\')">' + body + '</button>';
    }

    let inner = b('tarpit', 'Tarpit') + b('honeypot', 'Honeypot') + b('slop', 'Slop') + b('blacklist', 'Blacklist');
    if (includeClear) inner += b('clear', clearLbl);
    if (opts.flatten) return inner;
    const marginTop = opts.marginTop != null ? opts.marginTop : '8px';
    return '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:' + marginTop + ';align-items:center;">' + inner + '</div>';
}

/** One threat telemetry card: summary line + standard action buttons (same on Overview and Threat Monitor). */
function renderThreatTelemetryCard(t, buttonOpts){
    const ip = String(t.ip || '').trim();
    const mode = escapeHtml(t.mode || 'default');
    const hits = escapeHtml(t.hits != null ? t.hits : 0);
    const strikes = escapeHtml(t.strike_count != null ? t.strike_count : 0);
    const seen = threatTelemetryRelOrFallback(t.last_seen, threatTelemetryRelOrFallback(t.set_at, 'never'));
    const exp = threatTelemetryRelOrFallback(t.expires_at, 'n/a');
    const since = t.set_at ? threatTelemetryRelOrFallback(t.set_at, 'n/a') : 'n/a';
    const pathBit = t.last_path ? ', path=' + escapeHtml(t.last_path) : '';
    const clearLabel = (t.mode === 'blacklist') ? 'Remove blacklist' : 'Clear / reset';
    const line = '<strong>' + escapeHtml(ip) + '</strong> ' +
        'mode=<strong>' + mode + '</strong>, ' +
        'hits=' + hits + ', strikes=' + strikes + ', ' +
        'mode since ' + escapeHtml(since) + ', last protected hit ' + escapeHtml(seen) +
        pathBit + ', expires ' + escapeHtml(exp);
    const buttons = renderThreatIPActionButtonsHTML(ip, Object.assign({ clearButtonLabel: clearLabel }, buttonOpts || {}));
    return '<div style="margin:8px 0;padding:8px;border:1px solid #e2e5e8;border-radius:6px;">' + line + buttons + '</div>';
}

function refreshThreatRelatedViews(){
    if (!isAdminDashboardOpen()) return;
    if (adminActiveTab === 'overview') loadOverview();
    if (adminActiveTab === 'threats') loadThreats();
    if (adminActiveTab === 'devices') loadDevicePanel();
}

function applyInitialAdminTabOnce(){
    if (initialAdminTabApplied) return;
    initialAdminTabApplied = true;
    const t = VPNLESS_INITIAL_ADMIN_TAB;
    if (t !== 'overview') {
        setAdminTab(t);
    } else {
        syncAdminURLForTab('overview');
        loadOverview();
    }
}

async function loadOverview(){
    const pEl = document.getElementById('overviewPending');
    const aEl = document.getElementById('overviewNewApps');
    const cEl = document.getElementById('overviewCerts');
    const tEl = document.getElementById('overviewThreats');
    const wEl = document.getElementById('overviewWarning');
    if (!pEl || !aEl || !cEl || !tEl) return;
    const { res, data } = await api('/api/overview');
    if (!res.ok) {
        pEl.innerHTML = '<div class="empty">Could not load overview.</div>';
        aEl.innerHTML = '';
        cEl.innerHTML = '';
        tEl.innerHTML = '';
        return;
    }
    if (wEl) {
        if (data && data.warning) {
            wEl.textContent = data.warning;
            wEl.classList.remove('hidden');
        } else {
            wEl.classList.add('hidden');
            wEl.textContent = '';
        }
    }
    const pending = (data && Array.isArray(data.pending)) ? data.pending : [];
    if (pending.length === 0) {
        pEl.innerHTML = '<div class="empty"><p>No pending devices.</p></div>';
    } else {
        pEl.innerHTML = pending.map(function(d){
            const info = d.client_info || {};
            const nameHead = info.display_name ? '<div style="margin:0 0 6px;font-weight:600;">' + escapeHtml(info.display_name) + '</div>' : '';
            return '<div class="device" data-public-key="' + escapeAttr(d.public_key) + '">' + nameHead +
                '<div class="device-id">' + escapeHtml(d.device_id) + '</div>' +
                '<div>IP: ' + escapeHtml(d.remote_addr || 'Unknown') + ' · Pending ' + escapeHtml(dayjs(d.pending_at).fromNow()) + '</div>' +
                '<div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:8px;align-items:center;">' +
                '<button class="ok" onclick="approve(decodeURIComponent(\'' + enc(d.public_key) + '\'),decodeURIComponent(\'' + enc(d.device_id) + '\'))">Approve</button>' +
                '<button class="danger" onclick="openDenyModal(decodeURIComponent(\'' + enc(d.public_key) + '\'),decodeURIComponent(\'' + enc(d.device_id) + '\'))">Deny</button>' +
                renderThreatIPActionButtonsHTML(d.remote_addr, { buttonClass: 'secondary', flatten: true }) +
                '</div></div>';
        }).join('');
    }
    const newApps = (data && Array.isArray(data.new_apps)) ? data.new_apps : [];
    if (newApps.length === 0) {
        aEl.innerHTML = '<div class="empty"><p>No new labeled apps in the last 24h (by container create time).</p></div>';
    } else {
        aEl.innerHTML = '<div class="apps-grid">' + newApps.map(function(a){
            const href = String(a.href || '').trim();
            const icon = String(a.icon_url || '').trim();
            const img = icon ? '<img class="app-card-icon" src="' + escapeAttr(icon) + '" alt="" loading="lazy" referrerpolicy="no-referrer" />' : '';
            const nm = escapeHtml(a.name || 'App');
            if (!href) return '<div class="app-card">' + img + '<div class="app-card-name">' + nm + '</div></div>';
            return '<a class="app-card" href="' + escapeAttr(href) + '" target="_blank" rel="noopener noreferrer">' + img + '<div class="app-card-name">' + nm + '</div></a>';
        }).join('') + '</div>';
    }
    const certs = (data && Array.isArray(data.certificates)) ? data.certificates : [];
    if (certs.length === 0) {
        cEl.innerHTML = '<div class="empty"><p>No certificate issues detected.</p></div>';
    } else {
        cEl.innerHTML = certs.map(function(c){
            const st = c.status || 'unknown';
            const badge = '<span class="cert-badge ' + certBadgeClass(st) + '">' + escapeHtml(st) + '</span>';
            let sub = '';
            if (c.not_after) {
                const t = dayjs(c.not_after);
                if (t.isValid()) sub = 'Expires ' + escapeHtml(t.format('YYYY-MM-DD HH:mm')) + ' (' + escapeHtml(t.fromNow()) + ')';
            }
            return '<div class="cert-row ' + certRowAccentClass(st) + '"><div class="cert-meta"><strong class="mono">' + escapeHtml(c.host) + '</strong> ' + badge + (sub ? '<div style="margin-top:4px;">' + sub + '</div>' : '') + '</div></div>';
        }).join('');
    }
    const threats = (data && Array.isArray(data.recent_threats)) ? data.recent_threats.slice(0, 4) : [];
    if (threats.length === 0) {
        tEl.innerHTML = '<div class="empty"><p>No threat monitor rows yet (same store as Threat Monitor tab).</p></div>';
    } else {
        tEl.innerHTML = threats.map(function(t){
            return renderThreatTelemetryCard(t, { buttonClass: 'secondary sp' });
        }).join('');
    }
}

async function loadDevicePanel(){
    const wrap = document.getElementById('deviceFilterList');
    if (!wrap) return;
    if (deviceSubfilter === 'all') {
        const openRowKeys = collectOpenActivityRowKeys(wrap);
        const { res, data } = await api('/api/activity');
        if (!res.ok) { wrap.innerHTML = '<div class="empty">Could not load activity.</div>'; return; }
        const rows = Array.isArray(data) ? data : [];
        if (rows.length === 0) {
            wrap.innerHTML = '<div class="empty"><p>No pending, authorized, denied, or threat records.</p></div>';
            return;
        }
        const head = '<thead><tr><th>Last event</th><th>Status</th><th>Device ID</th><th>Public key</th><th>Remote</th><th>Note</th></tr></thead>';
        const body = rows.map(function(r){
            const st = escapeHtml(r.status || '');
            const cls = 'activity-status ' + (r.status || '');
            const et = r.event_time ? dayjs(r.event_time) : null;
            const timeCell = et && et.isValid() ? escapeHtml(et.format('YYYY-MM-DD HH:mm:ss')) : '—';
            const pk = String(r.public_key || '');
            const did = String(r.device_id || '');
            const remote = String(r.remote || '');
            const details = '<div style="display:grid;gap:8px;">' +
                '<div><strong>Device ID:</strong> <span class="mono">' + escapeHtml(did || '—') + '</span></div>' +
                '<div><strong>Public key:</strong> <span class="mono" style="word-break:break-all;">' + escapeHtml(pk || '—') + '</span></div>' +
                '<div><strong>Remote:</strong> ' + escapeHtml(remote || '—') + '</div>' +
                '<div><strong>Note:</strong> ' + escapeHtml(r.note || '') + '</div>' +
                renderActivityRowActions(r) +
                '</div>';
            const rowKey = activityRowKey(r);
            return '<tr class="activity-main-row" data-row-key="' + escapeAttr(rowKey) + '" onclick="toggleActivityDetails(this)" role="button" tabindex="0" onkeydown="if(event.key===\'Enter\'||event.key===\' \'){event.preventDefault();toggleActivityDetails(this);}">' +
                '<td>' + timeCell + '</td><td class="' + cls + '">' + st + '</td><td class="mono">' + escapeHtml(did) + '</td><td class="mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;">' + escapeHtml(pk) + '</td><td>' + escapeHtml(remote) + '</td><td>' + escapeHtml(r.note || '') + '</td></tr>' +
                '<tr class="activity-detail-row hidden"><td colspan="6">' + details + '</td></tr>';
        }).join('');
        wrap.innerHTML = '<div class="activity-table-wrap"><table class="activity-table">' + head + '<tbody>' + body + '</tbody></table></div>';
        restoreOpenActivityRowKeys(wrap, openRowKeys);
        return;
    }
    if (deviceSubfilter === 'pending') { await loadPendingInto(wrap); return; }
    if (deviceSubfilter === 'authorized') { await loadAuthorizedInto(wrap); return; }
    await loadDeniedInto(wrap);
}

function toggleActivityDetails(row){
    if (!row) return;
    const detail = row.nextElementSibling;
    if (!detail || !detail.classList.contains('activity-detail-row')) return;
    detail.classList.toggle('hidden');
}

function activityRowKey(r){
    return [
        String(r.status || ''),
        String(r.device_id || ''),
        String(r.public_key || ''),
        String(r.remote || '')
    ].join('|');
}

function collectOpenActivityRowKeys(wrap){
    const keys = new Set();
    if (!wrap) return keys;
    wrap.querySelectorAll('tr.activity-main-row[data-row-key]').forEach(function(row){
        const detail = row.nextElementSibling;
        if (!detail || !detail.classList.contains('activity-detail-row')) return;
        if (!detail.classList.contains('hidden')) {
            const k = row.getAttribute('data-row-key');
            if (k) keys.add(k);
        }
    });
    return keys;
}

function restoreOpenActivityRowKeys(wrap, keys){
    if (!wrap || !keys || keys.size === 0) return;
    wrap.querySelectorAll('tr.activity-main-row[data-row-key]').forEach(function(row){
        const k = row.getAttribute('data-row-key');
        if (!k || !keys.has(k)) return;
        const detail = row.nextElementSibling;
        if (detail && detail.classList.contains('activity-detail-row')) {
            detail.classList.remove('hidden');
        }
    });
}

function renderActivityRowActions(r){
    const status = String(r.status || '');
    const pk = String(r.public_key || '');
    const did = String(r.device_id || '');
    const remote = String(r.remote || '');
    if (status === 'pending' && pk && did) {
        return '<div style="display:flex;flex-wrap:wrap;gap:8px;">' +
            '<button class="ok" type="button" onclick="event.stopPropagation();approve(decodeURIComponent(\'' + enc(pk) + '\'),decodeURIComponent(\'' + enc(did) + '\'))">Approve</button>' +
            '<button class="danger" type="button" onclick="event.stopPropagation();openDenyModal(decodeURIComponent(\'' + enc(pk) + '\'),decodeURIComponent(\'' + enc(did) + '\'))">Deny</button>' +
            (remote ? renderThreatIPActionButtonsHTML(remote, { stopPropagation: true, buttonClass: 'secondary', flatten: true }) : '') +
            '</div>';
    }
    if (status === 'authorized' && pk && did) {
        return '<div style="display:flex;flex-wrap:wrap;gap:8px;">' +
            '<button class="danger" type="button" onclick="event.stopPropagation();disableAuthorized(decodeURIComponent(\'' + enc(pk) + '\'),decodeURIComponent(\'' + enc(did) + '\'))">Disable device</button>' +
            '</div>';
    }
    if (status === 'denied' && pk) {
        return '<div style="display:flex;flex-wrap:wrap;gap:8px;">' +
            '<button class="danger" type="button" onclick="event.stopPropagation();removeDeniedRecord(decodeURIComponent(\'' + enc(pk) + '\'))">Delete deny record</button>' +
            '</div>';
    }
    if (status === 'threat' && remote) {
        return renderThreatIPActionButtonsHTML(remote, { stopPropagation: true, buttonClass: 'secondary', marginTop: '0' });
    }
    return '<div class="msg">No direct actions for this row.</div>';
}

async function loadApps(){
    const wrap = document.getElementById('appsList');
    const warnEl = document.getElementById('appsWarning');
    if (!wrap) return;
    const { res, data } = await api('/api/apps');
    if (!res.ok) {
        wrap.innerHTML = '<div class="empty">Could not load apps (need admin session and Docker access from Caddy).</div>';
        if (warnEl) { warnEl.classList.add('hidden'); warnEl.textContent = ''; }
        return;
    }
    if (warnEl) {
        if (data && data.warning) {
            warnEl.textContent = data.warning;
            warnEl.classList.remove('hidden');
        } else {
            warnEl.classList.add('hidden');
            warnEl.textContent = '';
        }
    }
    const groups = (data && Array.isArray(data.groups)) ? data.groups : [];
    if (groups.length === 0) {
        wrap.innerHTML = '<div class="empty"><p>No apps found. Add <code>homepage.name</code> and <code>homepage.href</code> (and optional <code>homepage.group</code>, <code>homepage.icon</code>) to running containers. Mount the Docker socket into Caddy if needed.</p></div>';
        return;
    }
    wrap.innerHTML = groups.map(function(g){
        const title = escapeHtml(g.name || 'Services');
        const cards = (Array.isArray(g.apps) ? g.apps : []).map(function(a){
            const nm = escapeHtml(a.name || 'App');
            const href = String(a.href || '').trim();
            const icon = String(a.icon_url || '').trim();
            const desc = escapeHtml(a.description || '');
            const cid = a.container ? '<div class="app-card-meta">' + escapeHtml(a.container) + '</div>' : '';
            const img = icon ? '<img class="app-card-icon" src="' + escapeAttr(icon) + '" alt="" loading="lazy" referrerpolicy="no-referrer" />' : '';
            const descHtml = desc ? '<div class="app-card-desc">' + desc + '</div>' : '';
            if (!href) {
                return '<div class="app-card"><div class="app-card-name">' + nm + '</div>' + descHtml + cid + '<div class="app-card-desc">No homepage.href label</div></div>';
            }
            return '<a class="app-card" href="' + escapeAttr(href) + '" target="_blank" rel="noopener noreferrer">' + img + '<div class="app-card-name">' + nm + '</div>' + descHtml + cid + '</a>';
        }).join('');
        return '<h4 class="apps-section-title">' + title + '</h4><div class="apps-grid">' + cards + '</div>';
    }).join('');
}

function certRowAccentClass(status){
    if (status === 'no_certificate' || status === 'leaf_missing' || status === 'expired') return 'cert-bad';
    if (status === 'expiring_soon') return 'cert-warn';
    return 'cert-ok';
}
function certBadgeClass(status){
    if (status === 'no_certificate' || status === 'leaf_missing' || status === 'expired') return 'b-bad';
    if (status === 'expiring_soon') return 'b-warn';
    return 'b-ok';
}

function collectOpenCertDetailHosts(){
    const keys = new Set();
    const wrap = document.getElementById('certList');
    if (!wrap) return keys;
    wrap.querySelectorAll('details.cert-details[data-host]').forEach(function(el){
        if (el.open) {
            const h = el.getAttribute('data-host');
            if (h) keys.add(h);
        }
    });
    return keys;
}
function restoreOpenCertDetailHosts(keys){
    if (!keys || keys.size === 0) return;
    const wrap = document.getElementById('certList');
    if (!wrap) return;
    wrap.querySelectorAll('details.cert-details[data-host]').forEach(function(el){
        const h = el.getAttribute('data-host');
        if (h && keys.has(h)) el.open = true;
    });
}

async function loadCertificates(){
    const wrap = document.getElementById('certList');
    const warnEl = document.getElementById('certWarning');
    if (!wrap) return;
    const openHosts = collectOpenCertDetailHosts();
    const { res, data } = await api('/api/certificates');
    if (!res.ok) {
        wrap.innerHTML = '<div class="empty">Could not load certificates right now.</div>';
        if (warnEl) { warnEl.classList.add('hidden'); warnEl.textContent = ''; }
        return;
    }
    if (warnEl) {
        if (data && data.warning) {
            warnEl.textContent = data.warning;
            warnEl.classList.remove('hidden');
        } else {
            warnEl.classList.add('hidden');
            warnEl.textContent = '';
        }
    }
    const list = (data && Array.isArray(data.certificates)) ? data.certificates : [];
    if (list.length === 0) {
        wrap.innerHTML = '<div class="empty"><p>No host matchers found in the HTTP app, or nothing to show yet.</p></div>';
        return;
    }
    wrap.innerHTML = list.map(function(c){
        const host = escapeHtml(c.host);
        const st = c.status || 'unknown';
        const badge = '<span class="cert-badge ' + certBadgeClass(st) + '">' + escapeHtml(st) + '</span>';
        let headline = '<span class="mono">' + host + '</span>' + badge;
        let sub = '';
        if (c.not_after) {
            const t = dayjs(c.not_after);
            if (t.isValid()) {
                sub = 'Expires ' + escapeHtml(t.format('YYYY-MM-DD HH:mm')) + ' (' + escapeHtml(t.fromNow()) + ')';
                if (typeof c.days_remaining === 'number' && isFinite(c.days_remaining)) {
                    sub += ' · ' + escapeHtml(c.days_remaining.toFixed(1)) + ' days left';
                }
            }
        } else if (st === 'no_certificate' || st === 'leaf_missing') {
            sub = 'No matching certificate in Caddy\'s in-memory store for this host yet.';
        }
        const modes = Array.isArray(c.challenge_modes) ? c.challenge_modes.map(function(m){ return '<li>' + escapeHtml(m) + '</li>'; }).join('') : '';
        const issuers = Array.isArray(c.issuer_modules) ? c.issuer_modules.map(function(m){ return '<li class="mono">' + escapeHtml(m) + '</li>'; }).join('') : '';
        const subj = Array.isArray(c.subjects) && c.subjects.length ? '<div><strong>SANs / names:</strong> ' + escapeHtml(c.subjects.join(', ')) + '</div>' : '';
        const od = c.on_demand_policy ? '<div><strong>On-demand policy:</strong> yes</div>' : '';
        const detailBlock =
            '<div class="cert-meta">' +
            (c.challenge_summary ? '<div style="margin-bottom:8px;"><strong>Challenge / issuance:</strong> ' + escapeHtml(c.challenge_summary) + '</div>' : '') +
            (modes ? '<div><strong>Challenge modes (hint):</strong><ul style="margin:6px 0 0 18px;padding:0;">' + modes + '</ul></div>' : '') +
            (issuers ? '<div style="margin-top:8px;"><strong>Issuer modules:</strong><ul style="margin:6px 0 0 18px;padding:0;">' + issuers + '</ul></div>' : '') +
            od +
            (c.issuer ? '<div style="margin-top:8px;"><strong>Leaf issuer:</strong> ' + escapeHtml(c.issuer) + '</div>' : '') +
            (c.not_before ? '<div><strong>Not before:</strong> ' + escapeHtml(dayjs(c.not_before).format('YYYY-MM-DD HH:mm:ss')) + '</div>' : '') +
            subj +
            '</div>';
        const accent = certRowAccentClass(st);
        return '<div class="cert-row ' + accent + '"><details class="cert-details" data-host="' + escapeAttr(c.host) + '"><summary class="cert-summary">' + headline + '</summary><div class="cert-meta" style="margin-top:10px;">' + sub + '</div>' + detailBlock + '</details></div>';
    }).join('');
    restoreOpenCertDetailHosts(openHosts);
}

function scheduleAdminPoll(){
    stopAdminPoll();
    if (!isAdminDashboardOpen()) return;
    function loop(){
        if (!isAdminDashboardOpen()) {
            adminPollTimer = null;
            return;
        }
        adminPollTickAsync().catch(function(e){ console.error('VPNLess admin poll', e); }).then(function(){
            adminPollTimer = setTimeout(loop, pollDelayMs());
        });
    }
    adminPollTimer = setTimeout(loop, pollDelayMs());
}

document.addEventListener('visibilitychange', function(){
    if (!isAdminDashboardOpen()) return;
    stopAdminPoll();
    if (!document.hidden) {
        adminPollTick();
    }
    scheduleAdminPoll();
});

function applyLoginOtpVisibility(data){
    const row = document.getElementById('loginOtpRow');
    const input = document.getElementById('loginOtp');
    if (!row || !input) return;
    if (data && data.login_requires_otp) {
        row.classList.remove('hidden');
    } else {
        row.classList.add('hidden');
        input.value = '';
    }
}

async function refreshStatus(){
    const {res, data} = await api('/api/status');
    if (!res.ok || !data || !data.authenticated) {
        stopAdminPoll();
        initialAdminTabApplied = false;
        document.getElementById('loginPanel').classList.remove('hidden');
        document.getElementById('mainPanel').classList.add('hidden');
        applyLoginOtpVisibility(data);
        return;
    }
    document.getElementById('loginPanel').classList.add('hidden');
    document.getElementById('mainPanel').classList.remove('hidden');
    if (!data.otp_enabled) {
        document.getElementById('otpSetup').classList.remove('hidden');
        setupSecret = data.otp_secret || '';
        setupURI = data.otp_uri || '';
        document.getElementById('otpSecret').value = setupSecret;
    } else {
        document.getElementById('otpSetup').classList.add('hidden');
    }
    adminPollTick();
    scheduleAdminPoll();
    applyInitialAdminTabOnce();
}

async function login(){
    const body = {
        username: document.getElementById('loginUser').value,
        password: document.getElementById('loginPass').value,
        otp_code: document.getElementById('loginOtp').value
    };
    const {res} = await api('/api/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
    if (!res.ok) {
        if (res.status === 429) {
            showMessage('loginMsg', 'Too many tries — wait a bit and try again.');
        } else if (res.status === 401) {
            const needOtp = document.getElementById('loginOtpRow') && !document.getElementById('loginOtpRow').classList.contains('hidden');
            showMessage('loginMsg', needOtp ? 'Login failed. Check username, password, and OTP code.' : 'Login failed. Check username and password.');
        } else {
            showMessage('loginMsg', 'Login failed due to a server error.');
        }
        return;
    }
    showMessage('loginMsg', '');
    refreshStatus();
}

async function logout(){
    await api('/api/logout', {method:'POST'});
    refreshStatus();
}

async function enableOTP(){
    const code = document.getElementById('otpVerify').value;
    const {res} = await api('/api/otp/enable', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({otp_code:code})});
    if (!res.ok) { showMessage('otpMsg', 'OTP code verification failed.'); return; }
    showMessage('otpMsg', 'OTP is on.');
    refreshStatus();
}

async function copySecret(){
    if (!setupSecret) return;
    await navigator.clipboard.writeText(setupSecret);
    showMessage('otpMsg', 'OTP secret copied.');
}

function showQR(){
    if (!setupURI) {
        showMessage('otpMsg', 'No OTP URI yet — refresh the page after login.');
        return;
    }
    const QR = typeof QRCode !== 'undefined' ? QRCode : (typeof window !== 'undefined' && window.QRCode);
    if (!QR || typeof QR.toCanvas !== 'function') {
        showMessage('otpMsg', 'QR library failed to load. Check network / script blocker, or enter the secret manually.');
        return;
    }
    document.getElementById('qrModal').classList.remove('hidden');
    const el = document.getElementById('qrCanvas');
    el.innerHTML = '';
    QR.toCanvas(setupURI, { width: 220, margin: 2 }, function(err, canvas){
        if (err) {
            showMessage('otpMsg', 'Could not render QR: ' + (err.message || String(err)));
            return;
        }
        if (canvas) el.appendChild(canvas);
    });
}
function hideQR(e){
    if (e && e.target.id !== 'qrModal') return;
    document.getElementById('qrModal').classList.add('hidden');
}

function formatLastSeen(iso){
    if (!iso) return 'Never';
    const t = dayjs(iso);
    if (!t.isValid()) return 'Unknown';
    return t.fromNow() + ' (' + t.format('YYYY-MM-DD HH:mm') + ')';
}

/** Card border class: strong if latest activity used session proof / signature; weak if cookie was more recent. */
function authorizedCardAuthClass(d){
    const p = d.last_seen_session_proof ? dayjs(d.last_seen_session_proof).valueOf() : 0;
    const c = d.last_seen_cookie ? dayjs(d.last_seen_cookie).valueOf() : 0;
    if (!p && !c) return 'vpnless-unknown';
    if (p >= c) return 'vpnless-strong';
    return 'vpnless-weak';
}

function renderAuthorizedAuthBadges(d){
    const p = d.last_seen_session_proof;
    const c = d.last_seen_cookie;
    const strong = '<span class="auth-badge-strong" title="HMAC(session secret, v1|timestamp) or Ed25519">Session proof · ' + escapeHtml(formatLastSeen(p)) + '</span>';
    const weak = '<span class="auth-badge-weak" title="HTTP-only device token; replayable until revoked">Cookie · ' + escapeHtml(formatLastSeen(c)) + '</span>';
    const bits = [];
    if (p) bits.push(strong);
    if (c) bits.push(weak);
    if (bits.length === 0) bits.push('<span class="auth-badge-muted">No telemetry yet (upgrade server or wait for traffic)</span>');
    return '<div class="auth-badge-row">' + bits.join('') + '</div>';
}

async function loadAuthorizedInto(wrap){
    if (!wrap) return;
    const openDetailKeys = collectOpenDetailsPublicKeys(wrap);
    const nameEditKeys = collectAuthorizedNameEditKeys(wrap);
    const {res, data} = await api('/api/authorized');
    if (!res.ok) { wrap.innerHTML = '<div class="empty">Could not load authorized devices right now.</div>'; return; }
    if (!Array.isArray(data) || data.length === 0) {
        wrap.innerHTML = '<div class="empty"><p>No authorized devices yet.</p></div>';
        return;
    }
    wrap.innerHTML = data.map(d => {
        const last = formatLastSeen(d.last_seen);
        const info = d.client_info || {};
        const nameHead = info.display_name ? '<div style="margin:0 0 6px;font-weight:600;">' + escapeHtml(info.display_name) + '</div>' : '';
        const editingName = nameEditKeys.has(d.public_key);
        const authClass = authorizedCardAuthClass(d);
        return (
        '<div class="device ' + authClass + (editingName ? ' authorized-name-is-editing' : '') + '" data-public-key="' + escapeAttr(d.public_key) + '">' +
        nameHead +
        '<div class="device-id">' + escapeHtml(d.device_id) + '</div>' +
        renderAuthorizedAuthBadges(d) +
        '<div>Approved: ' + escapeHtml(dayjs(d.approved_at).fromNow()) + ' · Any activity: <strong>' + escapeHtml(last) + '</strong></div>' +
        (d.remote_addr ? '<div>IP (at approval): ' + escapeHtml(d.remote_addr) + '</div>' : '') +
        renderAuthorizedDeviceDetails(d) +
        '<div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:8px;align-items:center;">' +
        '<button type="button" class="secondary authorized-name-edit-btn" onclick="showAuthorizedNameEdit(this)">Edit</button>' +
        '<div class="authorized-name-edit-row">' +
        '<label style="margin:0;font-size:13px;white-space:nowrap;">Display name</label>' +
        '<input type="text" class="authorized-display-name" style="flex:1;min-width:120px;max-width:360px;padding:8px 10px;border:1px solid var(--input-border);border-radius:6px;background:var(--input-bg);color:var(--input-text);box-sizing:border-box;" maxlength="128" value="' + escapeAttr(info.display_name || '') + '" />' +
        '<button type="button" class="secondary" onclick="saveAuthorizedName(decodeURIComponent(\'' + enc(d.public_key) + '\'),decodeURIComponent(\'' + enc(d.device_id) + '\'),this)">Save</button>' +
        '<button type="button" class="secondary" onclick="cancelAuthorizedNameEdit(this)">Cancel</button>' +
        '</div></div>' +
        '<div style="margin-top:8px;"><button type="button" class="danger" onclick="disableAuthorized(decodeURIComponent(\'' + enc(d.public_key) + '\'),decodeURIComponent(\'' + enc(d.device_id) + '\'))">Disable device</button></div>' +
        '</div>'
        );
    }).join('');
    restoreDetailsOpenByPublicKey(wrap, openDetailKeys);
}

async function loadDeniedInto(wrap){
    if (!wrap) return;
    const { res, data } = await api('/api/denied');
    if (!res.ok) { wrap.innerHTML = '<div class="empty">Could not load denied pairings.</div>'; return; }
    const rows = Array.isArray(data) ? data : [];
    if (rows.length === 0) {
        wrap.innerHTML = '<div class="empty"><p>No pairing denials recorded.</p></div>';
        return;
    }
    wrap.innerHTML = rows.map(function(d){
        const pk = d.public_key || '';
        const when = d.denied_at ? dayjs(d.denied_at) : null;
        const whenStr = when && when.isValid() ? escapeHtml(when.format('YYYY-MM-DD HH:mm:ss')) + ' (' + escapeHtml(when.fromNow()) + ')' : '—';
        const active = d.active ? '<span class="activity-status pending">active</span>' : '<span class="activity-status authorized">inactive</span>';
        const strikes = escapeHtml(String(d.strike_count != null ? d.strike_count : ''));
        const msg = d.custom_message ? '<div style="margin-top:6px;font-size:13px;line-height:1.45;">' + escapeHtml(d.custom_message) + '</div>' : '';
        return '<div class="device" data-public-key="' + escapeAttr(pk) + '">' +
            '<div class="mono" style="font-size:12px;word-break:break-all;">' + escapeHtml(pk) + '</div>' +
            '<div style="margin-top:6px;">Denied ' + whenStr + ' · strikes=' + strikes + ' · ' + active + '</div>' +
            '<div style="margin-top:8px;"><button class="danger" type="button" onclick="removeDeniedRecord(decodeURIComponent(\'' + enc(pk) + '\'))">Delete deny record</button></div>' +
            msg + '</div>';
    }).join('');
}

async function removeDeniedRecord(publicKey){
    if (!publicKey) return;
    if (!confirm('Delete deny record for this public key?')) return;
    const { res } = await api('/api/denied/remove', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ public_key: publicKey })
    });
    if (!res.ok) { alert('Failed to remove deny record'); return; }
    refreshDeviceRelatedViews();
    if (deviceSubfilter === 'denied' && adminActiveTab === 'devices') {
        loadDeniedInto(document.getElementById('deviceFilterList'));
    }
}

function renderAuthorizedDeviceDetails(d){
    const info = d.client_info || {};
    const rows = [];
    function add(k, v){ if (v !== undefined && v !== null && String(v).trim() !== '') rows.push('<div><strong>' + escapeHtml(k) + ':</strong> ' + escapeHtml(v) + '</div>'); }
    add('Device ID', d.device_id);
    if (d.approved_at) {
        const t = dayjs(d.approved_at);
        if (t.isValid()) add('Approved at', t.format('YYYY-MM-DD HH:mm:ss') + ' (' + t.fromNow() + ')');
    }
    if (d.last_seen) {
        const t = dayjs(d.last_seen);
        if (t.isValid()) add('Last seen at', t.format('YYYY-MM-DD HH:mm:ss') + ' (' + t.fromNow() + ')');
    }
    if (d.last_seen_session_proof) {
        const t = dayjs(d.last_seen_session_proof);
        if (t.isValid()) add('Last session proof (HMAC / strong)', t.format('YYYY-MM-DD HH:mm:ss') + ' (' + t.fromNow() + ')');
    }
    if (d.last_seen_cookie) {
        const t = dayjs(d.last_seen_cookie);
        if (t.isValid()) add('Last cookie auth (weaker)', t.format('YYYY-MM-DD HH:mm:ss') + ' (' + t.fromNow() + ')');
    }
    add('IP (at approval)', d.remote_addr);
    add('Display name', info.display_name);
    add('Browser', [info.browser, info.browser_version].filter(Boolean).join(' '));
    add('OS', [info.os, info.os_version].filter(Boolean).join(' '));
    add('Screen', info.screen);
    add('Timezone', info.timezone);
    add('Languages', info.languages);
    add('CPU cores', info.hardware_concurrency);
    add('User-Agent', info.user_agent);
    add('X-Forwarded-For', info.x_forwarded_for);
    add('X-Real-IP', info.x_real_ip);
    add('Forwarded', info.forwarded);
    add('Peer remote (at pairing)', info.peer_remote_addr);
    add('Public key', d.public_key);
    return '<details class="authorized-device-details"><summary>Show full device details</summary><div style="margin-top:10px;font-size:13px;line-height:1.45;">' + rows.join('') + '</div></details>';
}

async function disableAuthorized(publicKey, deviceID){
    const {res} = await api('/api/authorized/revoke', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({public_key:publicKey, device_id:deviceID})});
    if (!res.ok) { alert('Failed to disable device'); return; }
    refreshDeviceRelatedViews();
}

async function saveAuthorizedName(publicKey, deviceID, btn){
    const wrap = btn && btn.closest ? btn.closest('.device') : null;
    const input = wrap ? wrap.querySelector('.authorized-display-name') : null;
    const name = input ? input.value : '';
    const {res} = await api('/api/authorized/display_name', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({public_key:publicKey, device_id:deviceID, display_name:name})});
    if (!res.ok) { alert('Failed to save display name'); return; }
    refreshDeviceRelatedViews();
}

async function loadPendingInto(wrap){
    if (!wrap) return;
    const openDetailKeys = collectOpenDetailsPublicKeys(wrap);
    const {res, data} = await api('/api/pending');
    if (!res.ok) { wrap.innerHTML = '<div class="empty">Could not load devices right now.</div>'; return; }
    if (!Array.isArray(data) || data.length === 0) { wrap.innerHTML = renderNoConnections(); return; }
    wrap.innerHTML = data.map(d => {
        const info = d.client_info || {};
        const nameHead = info.display_name ? '<div style="margin:0 0 6px;font-weight:600;">' + escapeHtml(info.display_name) + '</div>' : '';
        return (
        '<div class="device" data-public-key="' + escapeAttr(d.public_key) + '">' +
        nameHead +
        '<div class="device-id">' + escapeHtml(d.device_id) + '</div>' +
        '<div>IP: ' + escapeHtml(d.remote_addr || 'Unknown') + ' | Pending: ' + escapeHtml(dayjs(d.pending_at).fromNow()) + '</div>' +
        '<div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:8px;align-items:center;">' +
        '<label style="margin:0;font-size:13px;white-space:nowrap;">Display name</label>' +
        '<input type="text" class="pending-display-name" style="flex:1;min-width:160px;max-width:360px;padding:8px 10px;border:1px solid var(--input-border);border-radius:6px;background:var(--input-bg);color:var(--input-text);" maxlength="128" value="' + escapeAttr(info.display_name || '') + '" />' +
        '<button type="button" class="secondary" onclick="savePendingName(decodeURIComponent(\'' + enc(d.public_key) + '\'),decodeURIComponent(\'' + enc(d.device_id) + '\'),this)">Save name</button>' +
        '</div>' +
        renderDeviceDetails(d) +
        '<div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:8px;align-items:center;">' +
        '<button class="ok" onclick="approve(decodeURIComponent(\'' + enc(d.public_key) + '\'),decodeURIComponent(\'' + enc(d.device_id) + '\'))">Approve</button>' +
        '<button class="danger sp" onclick="openDenyModal(decodeURIComponent(\'' + enc(d.public_key) + '\'),decodeURIComponent(\'' + enc(d.device_id) + '\'))">Deny</button>' +
        renderThreatIPActionButtonsPendingHTML(d.public_key, d.device_id, d.remote_addr, { buttonClass: 'secondary sp', flatten: true }) +
        '</div>' +
        '</div>'
        );
    }).join('');
    restoreDetailsOpenByPublicKey(wrap, openDetailKeys);
}

function renderDeviceDetails(d){
    const info = d.client_info || {};
    const rows = [];
    function add(k, v){ if (v !== undefined && v !== null && String(v).trim() !== '') rows.push('<div><strong>' + escapeHtml(k) + ':</strong> ' + escapeHtml(v) + '</div>'); }
    add('Display name', info.display_name);
    add('Browser', [info.browser, info.browser_version].filter(Boolean).join(' '));
    add('OS', [info.os, info.os_version].filter(Boolean).join(' '));
    add('Screen', info.screen);
    add('Timezone', info.timezone);
    add('Languages', info.languages);
    add('CPU cores', info.hardware_concurrency);
    add('User-Agent', info.user_agent);
    add('X-Forwarded-For', info.x_forwarded_for);
    add('X-Real-IP', info.x_real_ip);
    add('Forwarded', info.forwarded);
    add('Peer remote', info.peer_remote_addr);
    add('Public key', d.public_key);
    if (rows.length === 0) return '';
    return '<details style="margin-top:8px;"><summary>Show device details</summary><div style="margin-top:6px;font-size:13px;line-height:1.45;">' + rows.join('') + '</div></details>';
}

async function approve(publicKey, deviceID){
    const {res} = await api('/api/approve', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({public_key:publicKey, device_id:deviceID})});
    if (!res.ok) { alert('Failed to approve device'); return; }
    refreshDeviceRelatedViews();
}

function renderDenySnarkList(pickedIndex) {
    const ul = document.getElementById('denySnarkList');
    if (!ul) return;
    ul.innerHTML = DENY_SNARKS.map(function(text, i) {
        const c = i === pickedIndex ? ' class="snark-picked"' : '';
        return '<li role="button" tabindex="0" data-snark-index="' + i + '"' + c + '>' + escapeHtml(text) + '</li>';
    }).join('');
}

function bindDenySnarkListOnce() {
    if (denySnarkListBound) return;
    const ul = document.getElementById('denySnarkList');
    if (!ul) return;
    denySnarkListBound = true;
    ul.addEventListener('click', function(ev) {
        const li = ev.target.closest('li');
        if (!li || !denyModalState) return;
        const i = parseInt(li.getAttribute('data-snark-index'), 10);
        if (isNaN(i) || i < 0 || i >= DENY_SNARKS.length) return;
        denyModalState.pickedIndex = i;
        renderDenySnarkList(i);
    });
    ul.addEventListener('keydown', function(ev) {
        if (ev.key !== 'Enter' && ev.key !== ' ') return;
        const li = ev.target.closest('li');
        if (!li || !denyModalState) return;
        ev.preventDefault();
        li.click();
    });
}

function openDenyModal(publicKey, deviceID) {
    const pickedIndex = Math.floor(Math.random() * DENY_SNARKS.length);
    denyModalState = { publicKey: publicKey, deviceID: deviceID, pickedIndex: pickedIndex };
    const ta = document.getElementById('denyCustomMsg');
    if (ta) ta.value = '';
    renderDenySnarkList(pickedIndex);
    bindDenySnarkListOnce();
    document.getElementById('denyModal').classList.remove('hidden');
    if (ta) ta.focus();
}

function hideDenyModal(e) {
    if (e && e.target.id !== 'denyModal') return;
    document.getElementById('denyModal').classList.add('hidden');
    denyModalState = null;
}

async function submitDeny() {
    if (!denyModalState) return;
    const publicKey = denyModalState.publicKey;
    const deviceID = denyModalState.deviceID;
    const ta = document.getElementById('denyCustomMsg');
    const extra = ta && ta.value ? ta.value.trim() : '';
    const body = { public_key: publicKey, device_id: deviceID, snark_index: denyModalState.pickedIndex };
    if (extra) body.deny_message = extra;
    const { res } = await api('/api/deny', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!res.ok) { alert('Failed to deny device'); return; }
    hideDenyModal();
    refreshDeviceRelatedViews();
}

async function savePendingName(publicKey, deviceID, btn){
    const wrap = btn && btn.closest ? btn.closest('.device') : null;
    const input = wrap ? wrap.querySelector('.pending-display-name') : null;
    const name = input ? input.value : '';
    const {res} = await api('/api/pending/display_name', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({public_key:publicKey, device_id:deviceID, display_name:name})});
    if (!res.ok) { alert('Failed to save display name'); return; }
    refreshDeviceRelatedViews();
}

function setThreatDurationPreset(preset){
    const input = document.getElementById('threatDurationInput');
    if (!input) return;
    input.value = String(preset || '');
    input.focus();
}

function normalizeThreatDurationForBackend(raw){
    let s = String(raw == null ? '' : raw).trim().toLowerCase();
    if (!s) return '8760h'; // default = 1 year

    // Pass through common Go-supported forms (e.g. 30m, 2h, 90s, 1h30m).
    if (/^\\d+(s|m|h)(\\d+)?$/.test(s) || /\\d+(h|m|s).+/.test(s)) {
        // If it's something like 1h30m, time.ParseDuration supports it; keep.
        return s;
    }

    // Admin-friendly units: d=days, w=weeks, m=months (30d), y=years (365d).
    let m = s.match(/^(\\d+)(d)$/);
    if (m) return String(Number(m[1]) * 24) + 'h';
    m = s.match(/^(\\d+)(w)$/);
    if (m) return String(Number(m[1]) * 7 * 24) + 'h';
    m = s.match(/^(\\d+)(m)$/); // months
    if (m) return String(Number(m[1]) * 30 * 24) + 'h';
    m = s.match(/^(\\d+)(y)$/);
    if (m) return String(Number(m[1]) * 365 * 24) + 'h';
    return s;
}

function showThreatDurationModal(ip, action, pendingCtx){
    threatDurationModalState = { ip: ip, action: action };
    if (pendingCtx && pendingCtx.publicKey && pendingCtx.deviceID) {
        threatDurationModalState.pendingPublicKey = pendingCtx.publicKey;
        threatDurationModalState.pendingDeviceID = pendingCtx.deviceID;
    }
    const modal = document.getElementById('threatDurationModal');
    if (!modal) return;
    modal.classList.remove('hidden');
    const input = document.getElementById('threatDurationInput');
    if (input) {
        input.value = '';
        input.focus();
    }
}

function hideThreatDurationModal(e){
    if (e && e.target && e.currentTarget && e.target !== e.currentTarget) return;
    const modal = document.getElementById('threatDurationModal');
    if (modal) modal.classList.add('hidden');
    threatDurationModalState = null;
}

async function submitThreatDuration(){
    if (!threatDurationModalState) return;
    const ip = threatDurationModalState.ip;
    const action = threatDurationModalState.action;
    const pendingPublicKey = threatDurationModalState.pendingPublicKey;
    const pendingDeviceID = threatDurationModalState.pendingDeviceID;
    const input = document.getElementById('threatDurationInput');
    const raw = input ? input.value : '';
    const duration = normalizeThreatDurationForBackend(raw);

    const payload = { ip: ip, action: action, duration: duration };
    const {res} = await api('/api/threats/action', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    if (!res.ok) { alert('Failed to apply threat action'); return; }

    if (pendingPublicKey && pendingDeviceID) {
        // Make Pending Approval behave like Approve/Deny: remove from pending list.
        const denyBody = { public_key: pendingPublicKey, device_id: pendingDeviceID };
        const {res: denyRes} = await api('/api/deny', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(denyBody)});
        if (!denyRes.ok) { alert('Failed to deny pending device'); return; }
        hideThreatDurationModal();
        refreshDeviceRelatedViews();
        // Optional: also refresh threat UI if it is open.
        refreshThreatRelatedViews();
        return;
    }

    hideThreatDurationModal();
    refreshThreatRelatedViews();
}

async function threatAction(ip, action){
    if (!ip) { alert('No IP available for this device'); return; }
    if (action === 'clear') {
        const payload = {ip: ip, action: action};
        const {res} = await api('/api/threats/action', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
        if (!res.ok) { alert('Failed to apply threat action'); return; }
        refreshThreatRelatedViews();
        return;
    }
    showThreatDurationModal(ip, action);
}

async function threatActionFromPendingDevice(publicKey, deviceID, ip, action){
    if (!ip) { alert('No IP available for this device'); return; }
    // Only tarpit/honeypot/slop/blacklist require a duration in our UI; clear is not shown in Pending.
    if (action === 'clear') { return threatAction(ip, action); }
    showThreatDurationModal(ip, action, { publicKey: publicKey, deviceID: deviceID });
}

function threatModeRank(mode){
    const o = {blacklist:0, tarpit:1, honeypot:2, slop:3, default:9};
    const m = String(mode || '');
    return o[m] !== undefined ? o[m] : 5;
}

async function loadThreats(){
    const wrap = document.getElementById('threatList');
    const {res, data} = await api('/api/threats');
    if (!res.ok) { wrap.textContent = 'Could not load threat telemetry right now.'; return; }
    if (!Array.isArray(data) || data.length === 0) { wrap.textContent = 'No threat entries yet.'; return; }
    const rows = data.slice().sort(function(a,b){
        const dr = threatModeRank(a.mode) - threatModeRank(b.mode);
        if (dr !== 0) return dr;
        const ta = new Date(a.last_seen || a.set_at || 0).getTime();
        const tb = new Date(b.last_seen || b.set_at || 0).getTime();
        return tb - ta;
    });
    wrap.innerHTML = rows.map(function(t){
        return renderThreatTelemetryCard(t, { buttonClass: 'secondary sp' });
    }).join('');
}

function tortureChamberCloseStream(){
    if (tortureChamberES) {
        tortureChamberES.close();
        tortureChamberES = null;
    }
}

function tortureAppendTranscriptLine(container, lineObj){
    if (!container || !lineObj) return;
    const row = document.createElement('div');
    row.className = lineObj.kind === 'in' ? 'torture-line-in' : 'torture-line-out';
    const t = lineObj.t ? (new Date(lineObj.t).toLocaleTimeString(undefined, { hour12:false }) + ' ') : '';
    row.textContent = t + (lineObj.text || '');
    container.appendChild(row);
    container.scrollTop = container.scrollHeight;
}

function closeTortureOverlay(ev){
    if (ev && ev.target && ev.currentTarget && ev.target !== ev.currentTarget) return;
    tortureChamberCloseStream();
    const o = document.getElementById('tortureOverlay');
    if (o) o.classList.add('hidden');
}

function openTortureChamberOverlay(sessionId, ip, mode, active){
    tortureChamberCloseStream();
    const title = document.getElementById('tortureOverlayTitle');
    const body = document.getElementById('tortureOverlayTranscript');
    const ovl = document.getElementById('tortureOverlay');
    if (!title || !body || !ovl || !sessionId) return;
    title.textContent = 'Torture · ' + ip + ' · ' + mode + (active ? ' (live)' : ' (ended)');
    body.innerHTML = '';
    ovl.classList.remove('hidden');
    const base = API_BASE.replace(/\/$/, '');
    const url = window.location.origin + base + '/api/torture/stream?session_id=' + encodeURIComponent(sessionId);
    const es = new EventSource(url);
    tortureChamberES = es;
    es.addEventListener('snapshot', function(ev){
        try {
            const lines = JSON.parse(ev.data);
            body.innerHTML = '';
            if (Array.isArray(lines)) lines.forEach(function(l){ tortureAppendTranscriptLine(body, l); });
        } catch (err) { console.error(err); }
    });
    es.addEventListener('line', function(ev){
        try { tortureAppendTranscriptLine(body, JSON.parse(ev.data)); } catch (e2) {}
    });
    es.addEventListener('done', function(){
        es.close();
        if (tortureChamberES === es) tortureChamberES = null;
    });
}

async function loadTortureChamber(){
    const wrap = document.getElementById('tortureChamberList');
    if (!wrap) return;
    const { res, data } = await api('/api/torture');
    if (!res.ok) { wrap.innerHTML = '<div class="empty">Could not load torture chamber.</div>'; return; }
    const sessions = (data && Array.isArray(data.sessions)) ? data.sessions : [];
    if (sessions.length === 0) {
        wrap.innerHTML = '<div class="empty"><p>No tarpit, honeypot, or slop sessions recorded yet on this worker. Torment someone from Threat Monitor, then hit a protected route without auth.</p></div>';
        return;
    }
    wrap.innerHTML = sessions.map(function(s){
        const rawSid = String(s.session_id || '');
        const rawIp = String(s.ip || '');
        const rawMode = String(s.mode || '');
        const pvLines = Array.isArray(s.preview_out_lines) ? s.preview_out_lines : [];
        const pv = pvLines.length ? escapeHtml(pvLines.join('\n')) : '';
        const active = s.active ? '1' : '0';
        const when = s.updated_at ? escapeHtml(dayjs(s.updated_at).fromNow()) : '—';
        const inN = escapeHtml(String(s.in_line_count != null ? s.in_line_count : 0));
        const outN = escapeHtml(String(s.out_line_count != null ? s.out_line_count : 0));
        return '<div class="torture-bot-card" role="button" tabindex="0" data-session-id="' + escapeAttr(rawSid) + '" data-ip="' + escapeAttr(rawIp) + '" data-mode="' + escapeAttr(rawMode) + '" data-active="' + active + '"' +
            ' onclick="openTortureChamberOverlayFromCard(this)" onkeydown="if(event.key===\'Enter\'||event.key===\' \'){event.preventDefault();openTortureChamberOverlayFromCard(this);}">' +
            '<div class="torture-bot-head">' + escapeHtml(rawIp) + ' · <span class="mono">' + escapeHtml(rawMode) + '</span>' + (s.active ? ' <span class="activity-status pending">live</span>' : '') + '</div>' +
            '<div class="torture-bot-meta">Last activity ' + when + ' · in lines ' + inN + ' · out lines ' + outN + '</div>' +
            '<pre class="torture-preview">' + (pv || escapeHtml('(no response bytes logged yet)')) + '</pre>' +
            '<div class="msg" style="margin:8px 0 0;font-size:12px;">Click for full-screen live transcript</div></div>';
    }).join('');
}

function openTortureChamberOverlayFromCard(el){
    if (!el) return;
    const sid = el.getAttribute('data-session-id');
    const ip = el.getAttribute('data-ip') || '';
    const mode = el.getAttribute('data-mode') || '';
    const active = el.getAttribute('data-active') === '1';
    openTortureChamberOverlay(sid, ip, mode, active);
}

document.addEventListener('keydown', function(ev){
    if (ev.key !== 'Escape') return;
    const o = document.getElementById('tortureOverlay');
    if (o && !o.classList.contains('hidden')) closeTortureOverlay();
    const m = document.getElementById('threatDurationModal');
    if (m && !m.classList.contains('hidden')) hideThreatDurationModal();
});

initTheme();
resetLoginFields();
refreshStatus();
</script>
</body>
</html>`
