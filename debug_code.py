from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
import base64

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

def broken_decrypt(encrypted_message_b64, user_id):
    try:
        # Decode the base64-encoded encrypted message
        encrypted_payload = base64.b64decode(encrypted_message_b64)
        
        # BROKEN: Incorrectly slice the payload, missing the salt
        iv = encrypted_payload[:16]  # Extract the IV (first 16 bytes)
        ciphertext = encrypted_payload[16:]  # Extract the ciphertext (remaining bytes)

        # BROKEN: Derive key without using the salt (it should be extracted from payload)
        salt = generate_salt()  # This generates a NEW salt (which is incorrect)
        key = derive_key(user_id, salt)  # Derive the key using the user ID and the new salt

        # Set up AES cipher in CBC mode with the derived key and IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        
        # Decrypt the ciphertext
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding from the decrypted message
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        # Return the decrypted message as a string
        return plaintext.decode('utf-8')
    except Exception as e:
        # Return error message if decryption fails
        return f"Decryption failed: {e}"
