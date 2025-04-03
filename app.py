from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64


import os

app = Flask(__name__)

# In-memory storage for messages
MESSAGE_STORE = {}
# In-memory storage for user salts (This is for key derivation)
USER_SALTS = {}

def generate_salt():
    return os.urandom(16)

def derive_key(user_id, salt=None):
    if salt is None:
        salt = USER_SALTS.get(user_id)
        if salt is None:
            raise ValueError("Salt not found for user")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(user_id.encode('utf-8'))
    return key

def encrypt_message(message, user_id):
    # Generate a unique salt for the user
    salt = generate_salt()
    
    # Store the salt associated with the user
    USER_SALTS[user_id] = salt
    
    # Derive an encryption key from the user ID and salt
    key = derive_key(user_id, salt)
    
    # Generate a random IV for AES encryption
    iv = os.urandom(16)
    
    # Set up AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    # Create encryptor and padder
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    
    # Pad the message and encrypt it
    padded_message = padder.update(message.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    # Combine salt, IV, and ciphertext, then base64 encode
    encrypted_payload = salt + iv + ciphertext
    return base64.b64encode(encrypted_payload).decode('utf-8')

