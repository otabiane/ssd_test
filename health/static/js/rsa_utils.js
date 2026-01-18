/**
 * Converts an ArrayBuffer to a Base64 encoded string.
 * Useful for storing or transmitting binary data in a textual format.
 * @param {ArrayBuffer} buffer - The buffer to be converted to Base64.
 * @returns {string} - Base64 encoded string.
 */
function arrayBufferToBase64 (buffer){
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
};
  
/**
 * Converts a Base64 encoded string to an ArrayBuffer.
 * This is used to convert textual binary data back into a usable ArrayBuffer.
 * @param {string} base64 - The Base64 string to be converted to ArrayBuffer.
 * @returns {ArrayBuffer} - The resulting ArrayBuffer.
 */
function base64ToArrayBuffer (base64) {
    const binary = window.atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
};

/**
 * Generates an RSA key pair (public and private keys) for encryption and decryption.
 * Exports the keys as Base64 strings for easy storage and usage.
 * @returns {Promise<{public_key: string, private_key: string}>} - The RSA key pair as Base64 strings.
 */
async function generateRSAKeyPair (){
    try {
        const encKey = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["encrypt", "decrypt"]
        );

        const publicKeyArrayBuffer = await window.crypto.subtle.exportKey("spki", encKey.publicKey);
        const privateKeyArrayBuffer = await window.crypto.subtle.exportKey("pkcs8", encKey.privateKey);

        return {
            public_key: arrayBufferToBase64(publicKeyArrayBuffer),
            private_key: arrayBufferToBase64(privateKeyArrayBuffer),
        };
    } catch (error) {
        throw new Error("Key generation failed.");
    }
};

/**
 * Encrypts data using the provided RSA public key.
 * @param {string} data - The plaintext data to be encrypted.
 * @param {CryptoKey} publicKey - The RSA public key used for encryption.
 * @returns {Promise<string>} - The encrypted data as a Base64 string.
 */

async function encryptWithPublicKey (data, publicKey) {
  const enc = new TextEncoder();
  const encoded = enc.encode(data);

  const encrypted = await window.crypto.subtle.encrypt(
      {
          name: "RSA-OAEP",
      },
      publicKey,
      encoded
  );

  return arrayBufferToBase64(encrypted);
};

/**
 * Imports a private RSA key from a Base64 string for use in decryption or signing.
 * @param {string} base64Key - The Base64-encoded private key.
 * @param {string} [useFor='decrypt'] - Specifies whether the key is used for 'decrypt' or 'sign'.
 * @returns {Promise<CryptoKey>} - The imported private key.
 */
async function importPrivateKey (base64Key, useFor = 'decrypt') {
    try {
        const keyBuffer = base64ToArrayBuffer(base64Key);
        let keyUsages;
        let algorithmName;

        if (useFor === 'decrypt') {
            keyUsages = ['decrypt'];
            algorithmName = 'RSA-OAEP';
        } else if (useFor === 'sign') {
            keyUsages = ['sign'];
            algorithmName = 'RSA-PSS';  // Or 'RSA-PSS' if you're using that
        } else {
            throw new Error('Invalid useFor parameter. Use "decrypt" or "sign".');
        }

        return await window.crypto.subtle.importKey(
            "pkcs8",
            keyBuffer,
            {
                name: algorithmName,
                hash: { name: "SHA-256" }
            },
            true,
            keyUsages
        );
    } catch (error) {
        throw new Error("Failed to import private key.");
    }
};

/**
 * Imports a public RSA key from a Base64 string for use in encryption or signature verification.
 * @param {string} base64Key - The Base64-encoded public key.
 * @param {string} [useFor='encrypt'] - Specifies whether the key is used for 'encrypt' or 'verify'.
 * @returns {Promise<CryptoKey>} - The imported public key.
 */
async function importPublicKey (base64Key, useFor = 'encrypt') {
    try {
        const keyBuffer = base64ToArrayBuffer(base64Key);
        let keyUsages;
        let algorithmName;

        if (useFor === 'encrypt') {
            keyUsages = ['encrypt'];
            algorithmName = 'RSA-OAEP';
        } else if (useFor === 'verify') {
            keyUsages = ['verify'];
            algorithmName = 'RSA-PSS';  // Or  if you're using that
        } else {
            throw new Error('Invalid useFor parameter. Use "encrypt" or "verify".');
        }

        return await window.crypto.subtle.importKey(
            "spki",
            keyBuffer,
            {
                name: algorithmName,
                hash: { name: "SHA-256" }
            },
            true,
            keyUsages
        );
    } catch (error) {
        throw new Error("Failed to import public key.");
    }
};

/**
 * Decrypts encrypted data using the provided RSA private key.
 * @param {string} encryptedData - The Base64-encoded encrypted data.
 * @param {CryptoKey} importedPrivateKey - The RSA private key used for decryption.
 * @returns {Promise<string>} - The decrypted plaintext data.
 */
async function decryptWithPrivateKey (encryptedData, importedPrivateKey) {  
    const decrypted = await window.crypto.subtle.decrypt(
        {
            name: "RSA-OAEP",
        },
        importedPrivateKey,
        base64ToArrayBuffer(encryptedData)
    );

    return new TextDecoder().decode(decrypted);
};

/**
 * Signs data using the provided RSA private key.
 * @param {string} data - The plaintext data to be signed.
 * @param {CryptoKey} privateKey - The RSA private key used for signing.
 * @returns {Promise<string>} - The generated signature as a Base64 string.
 */
async function signWithPrivateKey (data, privateKey) {
    try {
        const enc = new TextEncoder();
        const encoded = enc.encode(data);

        const signature = await window.crypto.subtle.sign(
            {
                name: "RSA-PSS",  // Ensure this matches with the key's algorithm
                saltLength: 32  
            },
            privateKey,
            encoded
        );

        return arrayBufferToBase64(signature);
    } catch (error) {
        throw new Error("Failed to sign data.");
    }
};

/**
 * Verifies a signature using the provided RSA public key.
 * @param {string} data - The plaintext data to verify.
 * @param {string} signatureBase64 - The Base64-encoded signature.
 * @param {CryptoKey} publicKeyBuffer - The RSA public key used for verification.
 * @returns {Promise<boolean>} - Whether the signature is valid or not.
 */

async function verifySignatureWithPublicKey (data, signatureBase64, publicKeyBuffer) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const signatureBuffer = base64ToArrayBuffer(signatureBase64);

  const isValid = await window.crypto.subtle.verify(
      {
          name: "RSA-PSS",
          saltLength: 32,
      },
      publicKeyBuffer,
      signatureBuffer,
      dataBuffer
  );

  return isValid;
};

/**
 * Checks which users have signed a specific piece of data.
 * Iterates through a list of signatures and verifies them against public keys.
 * @param {string[]} signatures - An array of Base64-encoded signatures.
 * @param {string} username - The username associated with the public key.
 * @param {string} data - The data that was signed.
 * @returns {Promise<string | null>} - The username of the valid signer, or null if no valid signer is found.
 */
async function checkSignatures (signatures, username, data) {
    // Loop through each signature and username
    for (let i = 0; i < signatures.length; i++) {
        const signature = signatures[i];
        const publicKeyBase64 = getSecret(`${username}_public_key`); 

        if (!publicKeyBase64) {
            continue;
        }

        // Import the public key
        const publicKey = await importPublicKey(publicKeyBase64, 'verify');

        // Verify the signature with the public key
        const isValid = await verifySignatureWithPublicKey(data, signature, publicKey);

        // If valid, add the username to the signedUsers array
        if (isValid) {
            return username;
        }
    }
    return null;
};
