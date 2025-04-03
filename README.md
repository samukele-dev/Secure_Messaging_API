# Secure Messaging API - Backend Coding Challenge

## Design Write-Up

**Encryption Method and Mode:**

I have chosen AES-256 in Cipher Block Chaining (CBC) mode for encrypting messages. AES (Advanced Encryption Standard) is a widely trusted and robust symmetric encryption algorithm, and using a 256-bit key length provides a high level of security against brute-force attacks. CBC mode is a common mode of operation for block ciphers. It works by XORing each plaintext block with the previous ciphertext block before encryption. This introduces dependency between blocks, making identical plaintext blocks produce different ciphertext blocks, thus enhancing security. An Initialization Vector (IV) is crucial in CBC mode to ensure that the encryption of the same plaintext with the same key results in different ciphertexts across multiple encryptions.

**Ensuring Only the Original User Can Access Messages:**

To ensure that only the original user can decrypt and retrieve their messages, the encryption key is derived uniquely for each user based on their `userId`. This is achieved using PBKDF2HMAC (Password-Based Key Derivation Function 2 with HMAC-SHA256). When a user sends their first message, a unique random salt is generated and associated with their `userId`. This salt is then used along with the `userId` as input to PBKDF2HMAC to derive a strong 256-bit encryption key. The generated salt is stored (in this in-memory implementation, in the `USER_SALTS` dictionary) and is also prepended to the encrypted payload before being stored. During decryption, the salt is extracted from the stored encrypted message, and the same PBKDF2HMAC process is used with the user's `userId` and the extracted salt to regenerate the exact same decryption key. Without knowing the correct `userId` and the associated salt (which is part of their encrypted messages), it is computationally infeasible to derive the correct decryption key.

**How the IV is Stored and Later Extracted:**

For each message encrypted, a fresh, cryptographically secure 16-byte Initialization Vector (IV) is generated. To ensure it can be used for decryption, the IV is embedded within the encrypted payload. The structure of the stored encrypted message (after base64 encoding) is as follows: `salt (16 bytes) + IV (16 bytes) + ciphertext`. During the decryption process:

1.  The base64 encoded message is decoded.
2.  The first 16 bytes of the decoded payload are extracted as the salt.
3.  The next 16 bytes are extracted as the IV.
4.  The remaining bytes are treated as the actual ciphertext.

These extracted components (salt, IV, and ciphertext) are then used in the AES-256-CBC decryption process along with the key derived from the `userId` and the extracted salt.

**How User ID Spoofing is Prevented:**

The current implementation, which relies on the client providing the `userId` in the request body without any further authentication, is **vulnerable to user ID spoofing**. A malicious user could potentially try to access another user's messages if they knew their `userId`.

To prevent user ID spoofing in a real-world application, a robust authentication mechanism is essential. Here are some common approaches:

* **Token-Based Authentication (e.g., JWT):** Upon successful login, the server would issue a unique, time-limited token to the user. Subsequent requests to access protected resources (like messages) would require the client to include this token in the `Authorization` header (typically as a Bearer token). The server would then verify the authenticity and validity of the token before processing the request, ensuring that the user making the request is indeed who they claim to be. The token would be associated with a specific `userId` on the server-side.
* **Session Management:** After login, the server creates a session for the user and stores a session identifier (e.g., in a cookie). Subsequent requests from the same user would include this session identifier, allowing the server to identify and authenticate the user based on the server-side session data.


## Debug Task

The `debug_code.py` file contains the `broken_decrypt()` function and its fix.

**Issue Identification:**

The `broken_decrypt()` function had the following critical flaws:

1.  **Incorrect Payload Slicing:** It attempted to extract the Initialization Vector (IV) by taking the first 16 bytes of the base64 decoded payload. However, the `encrypt_message()` function in `app.py` prepends the 16-byte salt *before* the IV. Therefore, `broken_decrypt()` was incorrectly treating the salt as the IV and the actual IV as part of the ciphertext.
2.  **Incorrect Key Derivation:** The `broken_decrypt()` function called `generate_salt()` during the decryption process. This would generate a *new*, random salt, which would be different from the salt used during encryption. Consequently, the `derive_key()` function would produce an incorrect decryption key, leading to the decryption failure. The correct approach is to use the salt that was used during encryption, which is embedded in the encrypted payload.

**Test Case:**

The `test_broken_decrypt()` function in `debug_code.py` sets up a scenario by:

1.  Generating a salt and deriving an encryption key for a specific `user_id`.
2.  Creating a plaintext message and padding it.
3.  Encrypting the padded plaintext using AES-256-CBC with a randomly generated IV.
4.  Constructing the encrypted payload by prepending the salt and the IV to the ciphertext.
5.  Base64 encoding the payload.
6.  Calling the `broken_decrypt()` function with this base64 encoded message and the correct `user_id`.
7.  The assertion `assert "Decryption failed" in decrypted_message or plaintext != decrypted_message` verifies that the `broken_decrypt()` function either explicitly indicates a decryption failure or produces a plaintext that is different from the original, demonstrating the broken logic.

**Fix Explanation (Implemented in `fixed_decrypt()`):**

```python
def fixed_decrypt(encrypted_message_b64, user_id):
    try:
        encrypted_payload = base64.b64decode(encrypted_message_b64)
        # FIXED: Extract the salt (first 16 bytes)
        salt = encrypted_payload[:16]
        # FIXED: Extract the IV (next 16 bytes)
        iv = encrypted_payload[16:32]
        # Extract the ciphertext (remaining bytes)
        ciphertext = encrypted_payload[32:]
        # FIXED: Derive the key using the extracted salt
        key = derive_key(user_id, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"Decryption failed: {e}"


## Instructions to Run the Project

1.  Open your terminal or command prompt.
2.  Navigate to the directory where you want to save the project.
3.  Run the following command :

    ```bash
    git clone https://github.com/samukele-dev/Secure_Messaging_API.git
    ```

4.  Once the repository is cloned, navigate into the project directory:

    ```bash
    cd secure_messaging_api
    ```

5.  Ensure you have Python 3.6+ installed.
6.  Navigate to the `secure_messaging_api` directory in your terminal.
7.  It is highly recommended to create and activate a virtual environment:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Linux/macOS
    venv\Scripts\activate   # On Windows
    ```
8.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```
9.  Run the Flask development server:
    ```bash
    python app.py
    ```
    The server will typically start at `http://127.0.0.1:5000`.
10.  You can then use tools like `curl`, Postman, or a web browser to interact with the API endpoints:
    * **POST /messages:** Send a JSON payload with `userId` and `message` to store a new encrypted message.
    * **GET /messages/<user_id>:** Replace `<user_id>` with the desired user's ID to retrieve their decrypted messages.
    * **POST /debug/decrypt:** Send a JSON payload with `userId` and a base64 encoded encrypted message to test the `broken_decrypt()` function. You can generate a test encrypted message using the `test_broken_decrypt()` function in `debug_code.py` or by storing a message via the `/messages` endpoint and copying the encrypted string.

Remember to stop the Flask development server by pressing `Ctrl + C` in your terminal when you are finished testing.