async function generateKeys() {
    let response = await fetch('/generate_keys', { method: 'POST' });
    let data = await response.json();
    document.getElementById('output').textContent = `Public Key 1:\n${data.public_key1}\n\nPublic Key 2:\n${data.public_key2}`;
}

async function encryptMessage() {
    let message = document.getElementById('message').value;
    let response = await fetch('/encrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: message })
    });
    let data = await response.json();
    document.getElementById('output').textContent = `Nonce:\n${data.nonce}\n\nCiphertext:\n${data.ciphertext}`;
}

async function decryptMessage() {
    let nonce = prompt("Enter the nonce:");
    let ciphertext = prompt("Enter the ciphertext:");
    let response = await fetch('/decrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nonce: nonce, ciphertext: ciphertext })
    });
    let data = await response.json();
    document.getElementById('output').textContent = `Decrypted Message:\n${data.message}`;
}

async function signMessage() {
    let message = document.getElementById('message').value;
    let response = await fetch('/sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: message })
    });
    let data = await response.json();
    document.getElementById('output').textContent = `Signature:\n${data.signature}`;
}

async function verifySignature() {
    let message = document.getElementById('message').value;
    let signature = prompt("Enter the signature:");
    let response = await fetch('/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: message, signature: signature })
    });
    let data = await response.json();
    document.getElementById('output').textContent = `Signature valid: ${data.valid}`;
}
