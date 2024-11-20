// Crypto utility functions
const CryptoUtils = {
    // Generate RSA key pair
    generateKeyPair: async () => {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
            },
            true,
            ["encrypt", "decrypt"]
        );
        return keyPair;
    },

    // Export public key
    exportPublicKey: async (key) => {
        const exported = await window.crypto.subtle.exportKey(
            "spki",
            key
        );
        return new Uint8Array(exported);
    },

    // Export private key
    exportPrivateKey: async (key) => {
        const exported = await window.crypto.subtle.exportKey(
            "pkcs8",
            key
        );
        return new Uint8Array(exported);
    },

    // Import public key
    importPublicKey: async (keyData) => {
        return await window.crypto.subtle.importKey(
            "spki",
            keyData,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            ["encrypt"]
        );
    },

    // Import private key
    importPrivateKey: async (keyData) => {
        return await window.crypto.subtle.importKey(
            "pkcs8",
            keyData,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            ["decrypt"]
        );
    },

    // Generate AES key for hybrid encryption
    generateAESKey: async () => {
        return await window.crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
    },

    // Export AES key
    exportAESKey: async (key) => {
        const exported = await window.crypto.subtle.exportKey("raw", key);
        return new Uint8Array(exported);
    },

    // Import AES key
    importAESKey: async (keyData) => {
        return await window.crypto.subtle.importKey(
            "raw",
            keyData,
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
    },

    // Encrypt data with AES-GCM
    encryptWithAES: async (key, data) => {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            data
        );
        return { encrypted, iv };
    },

    // Decrypt data with AES-GCM
    decryptWithAES: async (key, encryptedData, iv) => {
        return await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            encryptedData
        );
    },

    // Concatenate Uint8Arrays
    concatenateArrays: (...arrays) => {
        const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;
        arrays.forEach(arr => {
            result.set(arr, offset);
            offset += arr.length;
        });
        return result;
    },

    // Helper to create download
    downloadBlob: (blob, filename) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
};