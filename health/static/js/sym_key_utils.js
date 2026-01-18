const saltString  = "HEALTH_APP_STATIC_SALT";

async function exportKey (key){
    const exportedKey = await window.crypto.subtle.exportKey(
        'raw', // Export the key in its raw format
        key
    );
    return exportedKey;
};

async function importKey (rawKey){
    const key = await window.crypto.subtle.importKey(
        'raw',
        rawKey,
        {
          name: 'AES-GCM',
        },
        true,// Extractable
        ['encrypt', 'decrypt']
    );
    return key;
};

async function importHmacKey (rawKey) {
    return await window.crypto.subtle.importKey(
        'raw',
        rawKey,
        {
          name: 'HMAC',
          hash: { name: 'SHA-256' } // Ensure this matches the HMAC hash function
        },
        true, // Non-extractable for HMAC
        ['sign', 'verify']
    );
};

async function encryptData (data, key){
    const encoder = new TextEncoder(); // Encode the data as a Uint8Array
    const encoded_data = encoder.encode(data);
    
    const iv = await window.crypto.getRandomValues(new Uint8Array(12)); // Generate a random Initialization Vector (IV)

    const encrypted_data = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv  // Initialization vector
        },
        key,  // The AES key
        encoded_data  // Data to encrypt
    );

    return {
        encrypted_data: arrayBufferToBase64(new Uint8Array(encrypted_data)), // Convert to a Uint8Array for easier handling
        iv: arrayBufferToBase64(iv)  // Return the IV used for encryption
    };
};

async function decryptData (encryptedObject, key) {
    // Extract the encrypted data and IV from the provided object
    const encryptedBuffer = base64ToArrayBuffer(encryptedObject.encrypted_data);
    const ivBuffer = base64ToArrayBuffer(encryptedObject.iv);

    // Decrypt the data using the Web Crypto API
    const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: ivBuffer // Initialization vector (must be the same as used during encryption)
        },
        key,  // The AES key (CryptoKey)
        encryptedBuffer // Data to decrypt (ArrayBuffer or Uint8Array)
    );

    // Decode the decrypted data back to a string
    const decoder = new TextDecoder();
    const decryptedData = decoder.decode(decryptedBuffer);

    return decryptedData; // Return the decrypted string
};

async function derivePasswordKey(password, email) {
    const cleanPassword = password.trim();
    const cleanEmail = email.trim().toLowerCase();
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", enc.encode(cleanPassword), "PBKDF2", false, ["deriveKey"]
    );

    return await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: enc.encode(cleanEmail + saltString),
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256},
        false,
        ["encrypt", "decrypt"]
    );
}

async function deriveHashPassword(password, email) {
    const cleanPassword = password.trim();
    const cleanEmail = email.trim().toLowerCase();
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", enc.encode(cleanPassword), "PBKDF2", false, ["deriveKey"]
    );

    //Derive the key specifically for HMAC
    return await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: enc.encode(cleanEmail + saltString),
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "HMAC", hash: "SHA-256", length: 256},
        false,
        ["sign", "verify"]
    );
}

async function generateSymmetricKey (){
    const key = await window.crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256, // Length of the key in bits
      },
      true, // Whether the key is extractable (i.e., can be used for export)
      ['encrypt', 'decrypt'] // Usages
    );
    return key;
};

async function generateHMACKey (){
    return await window.crypto.subtle.generateKey(
      {
        name: 'HMAC',
        hash: { name: 'SHA-256' },
        length: 256,
      },
      true,
      ['sign', 'verify']
    );
};

async function generateMAC (message, key) {
    const enc = new TextEncoder();
    const messageBuffer = enc.encode(message);
    
    const mac = await window.crypto.subtle.sign(
      {
        name: 'HMAC',
        hash: { name: 'SHA-256' }
      },
      key,
      messageBuffer
    );
    
    return arrayBufferToBase64(mac);
};
  
async function verifyMAC (message, mac, key) {
  const enc = new TextEncoder();
  const messageBuffer = enc.encode(message);

  // Convert the provided MAC from Base64 to ArrayBuffer
  const macBuffer = base64ToArrayBuffer(mac);

  // Use the Web Crypto API to verify the HMAC
  const isValid = await window.crypto.subtle.verify(
    {
      name: 'HMAC',
      hash: { name: 'SHA-256' }, // Ensure this matches the hash used in HMAC
    },
    key,         // HMAC key
    macBuffer,   // The MAC to be verified (in ArrayBuffer form)
    messageBuffer // The original message data (in ArrayBuffer form)
  );

  return isValid;
};


async function deriveKeyFromWord (word) {
  try {
    // Convert word and salt to Uint8Array
    const encoder = new TextEncoder();
    const wordBuffer = encoder.encode(word);
    const saltBuffer = crypto.getRandomValues(new Uint8Array(16)); // Use a random salt if not provided

    // Import the word as raw key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      wordBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    // Derive the AES key from the word and salt
    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations: 100000, // Use a high number of iterations for security
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    return {
      derivedKey,
      salt: arrayBufferToBase64(saltBuffer) // Return the salt for future use
    };
  } catch (error) {
    throw new Error('Failed to derive AES key.');
  }
};

function readFileAsArrayBuffer (file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
};

async function encryptImage (file, key) {
  const data = await readFileAsArrayBuffer(file);
  const iv = crypto.getRandomValues(new Uint8Array(12)); 

  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    data
  );
  
  // Combine IV and encrypted data
  const combinedBuffer = new Uint8Array(iv.byteLength + encryptedBuffer.byteLength);
  combinedBuffer.set(new Uint8Array(iv), 0);
  combinedBuffer.set(new Uint8Array(encryptedBuffer), iv.byteLength);

  return combinedBuffer;
};

async function decryptAndDisplayImage (combinedBuffer, key) {
  try {
    const decryptedData = await decryptImage(combinedBuffer, key);
    const blob = new Blob([decryptedData]);
    const url = URL.createObjectURL(blob);
    return url;
  } catch (error) {
    console.error('Decryption failed', error);
  }
};

function extractIVAndEncryptedContent (combinedBuffer){
  const iv = combinedBuffer.slice(0, 12);
  const encryptedContent = combinedBuffer.slice(12);
  return { iv, encryptedContent };
};

async function decryptImage (combinedBuffer, key){
  const { iv, encryptedContent } = extractIVAndEncryptedContent(combinedBuffer);
  
  let cryptoKey;
  if(key instanceof CryptoKey) {
    cryptoKey = key;
  } else {
    cryptoKey = await importKey(key);
  }

  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    cryptoKey,
    encryptedContent
  );

  return new Uint8Array(decryptedBuffer);
};

async function encryptAndSignKey (key, publicKey, privateKey) {
    try {
        const exportedKey = await exportKey(key);
        const base64Key = arrayBufferToBase64(exportedKey);      
        const encryptedKey = await encryptWithPublicKey(base64Key, publicKey);   
        const signedKey = await signWithPrivateKey(encryptedKey, privateKey);        
        return { key: encryptedKey, signature: signedKey };
    } catch (error) {
        throw new Error("Failed to encrypt and sign the key.");
    }
};

async function decryptAndVerifyKey (encryptedKey, signedKey, publicKey, privateKey) {
    try {
        const isKeyValid = await verifySignatureWithPublicKey(encryptedKey, signedKey, publicKey);
        if (!isKeyValid) throw new Error('Key verification failed.');

        const decryptedBase64Key = await decryptWithPrivateKey(encryptedKey, privateKey);
        const decryptedKeyBuffer = base64ToArrayBuffer(decryptedBase64Key);
        const importedKey = await importKey(decryptedKeyBuffer);
        
        return importedKey;
    } catch (error) {
        throw new Error('Failed to decrypt and verify key.');
    }
};

function toUrlSafeBase64(base64) {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromUrlSafeBase64(base64Url) {
    let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
        base64 += '=';
    }
    return base64;
}

async function encryptFilename(name, key) {
    const enc = new TextEncoder();
    const encoded = enc.encode(name);
    
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encoded
    );

    const combined = new Uint8Array(iv.byteLength + encryptedContent.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encryptedContent), iv.byteLength);

    return toUrlSafeBase64(arrayBufferToBase64(combined.buffer));
}

async function decryptFilename(safeName, key) {
    try {
        const standardBase64 = fromUrlSafeBase64(safeName);
        const combinedBuffer = base64ToArrayBuffer(standardBase64);
        
        const iv = combinedBuffer.slice(0, 12);
        const data = combinedBuffer.slice(12);

        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            data
        );

        return new TextDecoder().decode(decrypted);
    } catch (e) {
        console.error("Filename decryption failed:", e);
        return "Unknown_File"; // Fallback
    }
}