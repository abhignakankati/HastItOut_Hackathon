// UI helper functions
function showStatus(message, type = 'info') {
    const statusDiv = document.getElementById('status');
    statusDiv.textContent = message;
    statusDiv.style.display = 'block';
    statusDiv.className = 'status ' + type;
}

function updateProgress(percent) {
    const progressContainer = document.getElementById('progress-container');
    const progressFill = document.getElementById('progress-fill');
    
    progressContainer.style.display = 'block';
    progressFill.style.width = `${percent}%`;
    
    if (percent >= 100) {
        setTimeout(() => {
            progressContainer.style.display = 'none';
            progressFill.style.width = '0%';
        }, 1000);
    }
}

// Key pair management
let currentKeyPair = null;

async function generateKeyPair() {
    try {
        showStatus('Generating key pair...', 'info');
        currentKeyPair = await CryptoUtils.generateKeyPair();
        showStatus('Key pair generated successfully! You can now download the keys.', 'success');
    } catch (error) {
        showStatus('Error generating key pair: ' + error.message, 'error');
    }
}

async function downloadKeys() {
    if (!currentKeyPair) {
        showStatus('Please generate a key pair first', 'error');
        return;
    }

    try {
        // Export and download public key
        const publicKeyData = await CryptoUtils.exportPublicKey(currentKeyPair.publicKey);
        const publicKeyBlob = new Blob([publicKeyData], { type: 'application/octet-stream' });
        CryptoUtils.downloadBlob(publicKeyBlob, 'public_key.pub');

        // Export and download private key
        const privateKeyData = await CryptoUtils.exportPrivateKey(currentKeyPair.privateKey);
        const privateKeyBlob = new Blob([privateKeyData], { type: 'application/octet-stream' });
        CryptoUtils.downloadBlob(privateKeyBlob, 'private_key.priv');

        showStatus('Keys downloaded successfully!', 'success');
    } catch (error) {
        showStatus('Error downloading keys: ' + error.message, 'error');
    }
}

// File encryption function
async function encryptFile() {
    const fileInput = document.getElementById('fileInput');
    const publicKeyInput = document.getElementById('publicKeyInput');
    
    if (!fileInput.files.length) {
        showStatus('Please select a file to encrypt', 'error');
        return;
    }

    if (!publicKeyInput.files.length && !currentKeyPair) {
        showStatus('Please provide a public key or generate a key pair', 'error');
        return;
    }

    try {
        showStatus('Encrypting file...', 'info');
        updateProgress(0);

        // Get public key
        let publicKey;
        if (currentKeyPair) {
            publicKey = currentKeyPair.publicKey;
        } else {
            const publicKeyFile = await publicKeyInput.files[0].arrayBuffer();
            publicKey = await CryptoUtils.importPublicKey(new Uint8Array(publicKeyFile));
        }

        updateProgress(20);

        // Generate AES key for hybrid encryption
        const aesKey = await CryptoUtils.generateAESKey();
        const exportedAesKey = await CryptoUtils.exportAESKey(aesKey);
        
        updateProgress(30);

        // Encrypt AES key with RSA
        const encryptedAesKey = await window.crypto.subtle.encrypt(
            {
                name: "RSA-OAEP"
            },
            publicKey,
            exportedAesKey
        );

        updateProgress(40);

        // Read and encrypt file with AES
        const fileData = await fileInput.files[0].arrayBuffer();
        const { encrypted, iv } = await CryptoUtils.encryptWithAES(aesKey, fileData);
        
        updateProgress(70);

        // Combine encrypted AES key, IV, and encrypted file
        const encryptedAesKeyLength = new Uint8Array(new Uint32Array([encryptedAesKey.byteLength]).buffer);
        const finalData = CryptoUtils.concatenateArrays(
            encryptedAesKeyLength,
            new Uint8Array(encryptedAesKey),
            iv,
            new Uint8Array(encrypted)
        );

        updateProgress(90);

        // Create and download encrypted file
        const blob = new Blob([finalData], { type: 'application/octet-stream' });
        CryptoUtils.downloadBlob(blob, fileInput.files[0].name + '.encrypted');

        updateProgress(100);
        showStatus('File encrypted successfully!', 'success');
    } catch (error) {
        showStatus('Error encrypting file: ' + error.message, 'error');
    }
}

// File decryption function
async function decryptFile() {
    const fileInput = document.getElementById('fileInput');
    const privateKeyInput = document.getElementById('privateKeyInput');
    
    if (!fileInput.files.length) {
        showStatus('Please select a file to decrypt', 'error');
        return;
    }

    if (!privateKeyInput.files.length && !currentKeyPair) {
        showStatus('Please provide a private key or generate a key pair', 'error');
        return;
    }

    try {
        showStatus('Decrypting file...', 'info');
        updateProgress(0);

        // Get private key
        let privateKey;
        if (currentKeyPair) {
            privateKey = currentKeyPair.privateKey;
        } else {
            const privateKeyFile = await privateKeyInput.files[0].arrayBuffer();
            privateKey = await CryptoUtils.importPrivateKey(new Uint8Array(privateKeyFile));
        }

        updateProgress(20);

        // Read encrypted file
        const encryptedData = new Uint8Array(await fileInput.files[0].arrayBuffer());
        
        // Extract encrypted AES key length
        const encryptedAesKeyLength = new Uint32Array(encryptedData.slice(0, 4).buffer)[0];
        let offset = 4;
        
        // Extract encrypted AES key
        const encryptedAesKey = encryptedData.slice(offset, offset + encryptedAesKeyLength);
        offset += encryptedAesKeyLength;
        
        // Extract IV and encrypted file data
        const iv = encryptedData.slice(offset, offset + 12);
        const encryptedFile = encryptedData.slice(offset + 12);

        updateProgress(40);

        // Decrypt AES key
        const aesKeyData = await window.crypto.subtle.decrypt(
            {
                name: "RSA-OAEP"
            },
            privateKey,
            encryptedAesKey
        );
        const aesKey = await CryptoUtils.importAESKey(new Uint8Array(aesKeyData));

        updateProgress(60);

        // Decrypt file
        const decryptedData = await CryptoUtils.decryptWithAES(aesKey, encryptedFile, iv);

        updateProgress(80);

        // Create and download decrypted file
        const blob = new Blob([decryptedData], { type: 'application/octet-stream' });
        CryptoUtils.downloadBlob(blob, fileInput.files[0].name.replace('.encrypted', ''));

        updateProgress(100);
        showStatus('File decrypted successfully!', 'success');
    } catch (error) {
        showStatus('Error decrypting file: ' + error.message, 'error');
    }
}

// Add drag and drop support
const fileInput = document.getElementById('fileInput');
const dropZone = fileInput.parentElement;

['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, preventDefaults, false);
});

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, highlight, false);
});

['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, unhighlight, false);
});

function highlight(e) {
    dropZone.classList.add('bg-blue-50');
}

function unhighlight(e) {
    dropZone.classList.remove('bg-blue-50');
}

dropZone.addEventListener('drop', handleDrop, false);

function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;
    fileInput.files = files;
}