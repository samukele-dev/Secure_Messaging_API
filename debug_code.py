from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

# Store debug keys for users
USER_DEBUG_KEYS = {}

# Generate a random salt (16 bytes)
def generate_salt():
    return os.urandom(16)

# Derive a cryptographic key from the user's ID and salt using PBKDF2
def derive_key(user_id, salt):
    # Set up PBKDF2HMAC key derivation function
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use SHA-256 hashing algorithm
        length=32,  # Key length (32 bytes)
        salt=salt,  # Salt for randomness
        iterations=100000,  # Number of iterations for security
        backend=default_backend()  # Use default cryptographic backend
    )
    # Derive the key from the user ID
    key = kdf.derive(user_id.encode('utf-8'))
    return key
