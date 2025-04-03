// Node sample: npm install ed25519

const ed25519 = require('ed25519');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class NodeDeviceAuthClient {
    constructor(storagePath = './device_keypair.json') {
        this.storagePath = storagePath;
        this.keyPair = null;
    }

    getKeyPair() {
        if (this.keyPair) {
            return this.keyPair;
        }

        // Try to load from file
        if (fs.existsSync(this.storagePath)) {
            const stored = JSON.parse(fs.readFileSync(this.storagePath, 'utf8'));
            this.keyPair = {
                publicKey: Buffer.from(stored.publicKey, 'base64'),
                privateKey: Buffer.from(stored.privateKey, 'base64'),
                publicKeyB64: stored.publicKey,
                privateKeyB64: stored.privateKey
            };
            return this.keyPair;
        }

        // Generate new key pair
        const keyPair = ed25519.MakeKeypair();
        this.keyPair = {
            publicKey: keyPair.publicKey,
            privateKey: keyPair.privateKey,
            publicKeyB64: keyPair.publicKey.toString('base64'),
            privateKeyB64: keyPair.privateKey.toString('base64')
        };

        // Save to file
        fs.writeFileSync(this.storagePath, JSON.stringify({
            publicKey: this.keyPair.publicKeyB64,
            privateKey: this.keyPair.privateKeyB64
        }), 'utf8');

        return this.keyPair;
    }

    signMessage(message) {
        const keyPair = this.getKeyPair();
        const signature = ed25519.Sign(Buffer.from(message), keyPair.privateKey);
        return signature.toString('base64');
    }

    computeDeviceID(publicKeyB64) {
        const hash = crypto.createHash('sha256');
        hash.update(publicKeyB64);
        return hash.digest('base64url').substring(0, 16);
    }

    async authenticatedRequest(url, options = {}) {
        const keyPair = this.getKeyPair();
        const timestamp = Date.now().toString();
        const signature = this.signMessage(timestamp);

        const headers = {
            'X-Device-Public-Key': keyPair.publicKeyB64,
            'X-Device-Sig': signature,
            'X-Device-Timestamp': timestamp,
            ...options.headers
        };

        // Using node-fetch or similar
        const fetch = require('node-fetch');
        return fetch(url, {
            ...options,
            headers
        });
    }
}

// Usage example
async function main() {
    const client = new NodeDeviceAuthClient();
    const keyPair = client.getKeyPair();
    const deviceID = client.computeDeviceID(keyPair.publicKeyB64);

    console.log('Device ID:', deviceID);
    console.log('Public Key:', keyPair.publicKeyB64.substring(0, 32) + '...');

    try {
        const response = await client.authenticatedRequest('http://localhost:8080/api/data');
        
        if (response.ok) {
            const data = await response.json();
            console.log('Success:', data);
        } else if (response.status === 403) {
            console.log('Device not authorized. Device ID:', deviceID);
            console.log('Please approve this device in the admin console.');
        } else {
            console.log('Request failed:', response.status, response.statusText);
        }
    } catch (error) {
        console.error('Request error:', error.message);
    }
}

// Run if called directly
if (require.main === module) {
    main();
}

module.exports = NodeDeviceAuthClient;
