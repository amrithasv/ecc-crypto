from flask import Flask, request, jsonify, render_template
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os
import base64

app = Flask(__name__)

# Generate ECC key pairs for two parties
private_key1, public_key1 = ec.generate_private_key(ec.SECP256R1(), default_backend()), None
private_key2, public_key2 = ec.generate_private_key(ec.SECP256R1(), default_backend()), None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    global private_key1, public_key1, private_key2, public_key2
    private_key1 = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key1 = private_key1.public_key()
    private_key2 = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key2 = private_key2.public_key()
    return jsonify({
        "public_key1": public_key1.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        "public_key2": public_key2.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    })

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    data = request.get_json()
    message = data['message'].encode()
    
    shared_key = private_key1.exchange(ec.ECDH(), public_key2)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    aesgcm = AESGCM(derived_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message, None)

    return jsonify({
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    })

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    data = request.get_json()
    nonce = base64.b64decode(data['nonce'])
    ciphertext = base64.b64decode(data['ciphertext'])
    
    shared_key = private_key2.exchange(ec.ECDH(), public_key1)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    aesgcm = AESGCM(derived_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return jsonify({"message": plaintext.decode()})

@app.route('/sign', methods=['POST'])
def sign_message():
    data = request.get_json()
    message = data['message'].encode()

    signature = private_key1.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

    return jsonify({"signature": base64.b64encode(signature).decode()})

@app.route('/verify', methods=['POST'])
def verify_signature():
    data = request.get_json()
    message = data['message'].encode()
    signature = base64.b64decode(data['signature'])

    try:
        public_key1.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return jsonify({"valid": True})
    except Exception as e:
        return jsonify({"valid": False})

if __name__ == '__main__':
    app.run(debug=True)
