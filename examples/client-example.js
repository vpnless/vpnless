// Sketch of a browser-side client: Ed25519 headers for VPNLess.
// Pairing flow in production should use the real pairing page + vpnless-client-auth.js for session HMAC.

class DeviceAuthClient {
    constructor(storageKey = 'device_auth_keypair') {
        this.storageKey = storageKey;
        this.keyPair = null;
    }

    async getKeyPair() {
        if (this.keyPair) {
            return this.keyPair;
        }

        const stored = localStorage.getItem(this.storageKey);
        if (stored) {
            this.keyPair = JSON.parse(stored);
            return this.keyPair;
        }

        this.keyPair = await this.generateKeyPair();
        localStorage.setItem(this.storageKey, JSON.stringify(this.keyPair));
        return this.keyPair;
    }

    // Prefer Web Crypto + a real Ed25519 lib; the random fallback below is only to keep the file runnable.
    async generateKeyPair() {
        if (typeof crypto !== 'undefined' && crypto.subtle) {
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

                return {
                    publicKey: this.arrayBufferToBase64(publicKeyRaw),
                    privateKey: this.arrayBufferToBase64(privateKeyRaw),
                    keyPair: keyPair
                };
            } catch (error) {
                console.warn('Web Crypto API not available, using fallback');
            }
        }

        const publicKey = this.generateRandomBase64(32);
        const privateKey = this.generateRandomBase64(64);

        return { publicKey, privateKey };
    }

    async signMessage(message) {
        const keyPair = await this.getKeyPair();

        if (keyPair.keyPair && typeof crypto !== 'undefined' && crypto.subtle) {
            const encoder = new TextEncoder();
            const signature = await crypto.subtle.sign(
                "Ed25519",
                keyPair.keyPair.privateKey,
                encoder.encode(message)
            );
            return this.arrayBufferToBase64(signature);
        }

        console.warn('Fallback signing — not a real Ed25519 signature');
        return this.generateRandomBase64(64);
    }

    async authenticatedFetch(url, options = {}) {
        const keyPair = await this.getKeyPair();
        const timestamp = Date.now().toString();
        const signature = await this.signMessage(timestamp);

        const headers = {
            'X-Device-Public-Key': keyPair.publicKey,
            'X-Device-Sig': signature,
            'X-Device-Timestamp': timestamp,
            ...options.headers
        };

        return fetch(url, {
            ...options,
            headers
        });
    }

    computeDeviceID(publicKey) {
        let hash = 0;
        for (let i = 0; i < publicKey.length; i++) {
            const char = publicKey.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return Math.abs(hash).toString(36).substring(0, 16);
    }

    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    generateRandomBase64(length) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return btoa(String.fromCharCode(...array));
    }
}

async function example() {
    const client = new DeviceAuthClient();

    try {
        const response = await client.authenticatedFetch('https://example.com/api/data');
        if (response.ok) {
            const data = await response.json();
            console.log('Success:', data);
        } else if (response.status === 403) {
            console.log('Device not authorized — approve in admin.');
            const deviceID = client.computeDeviceID((await client.getKeyPair()).publicKey);
            console.log('Device ID:', deviceID);
        }
    } catch (error) {
        console.error('Request failed:', error);
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = DeviceAuthClient;
}
