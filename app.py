from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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

