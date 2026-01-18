// based on: rsa_utils.js
// sym_key_utils.js
function isPasswordStrong(password) {
    const minLength = 12; // Health standards usually require 12+
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password.length < minLength) {
        Swal.fire('Data format', 'Password must be at least 12 characters.', 'error');
        return false;
    }
    if (!(hasUpperCase && hasLowerCase && hasNumbers && hasSpecial)) {
        Swal.fire('Data format', 'Password must include upper, lower, number, and special characters.', 'error');
        return false;
    }
    return true;
}

function isStringClean(value, maxLength = 255, allowSpaces=true) {
    if (typeof value !== 'string') return "";
    let clean = value.trim();
    clean = clean.substring(0, maxLength);
    const regex = allowSpaces ? /^[a-zA-Z0-9\s]+$/ : /^[a-zA-Z0-9]+$/;
    return regex.test(value);
}

function isDateCorrect(dateValue) {
    const baseCheck = /^[0-9-]+$/;
    // Only allows digits 0-9 and the '-' character
    const test1 = baseCheck.test(dateValue);

    //Strict Format Check (YYYY-MM-DD)
    const test2 = dateValue.length == 10;

    //Logical Date Validation
    const date = new Date(dateValue);
    const test3 = !isNaN(date.getTime());

    //Prevention of "Date Shifting"
    const backToString = date.toISOString().split('T')[0];
    const test4 = backToString === dateValue;

    return test1 && test2 && test3 && test4;
}

/**
 * Sanitizes and normalizes an email address.
 * Removes illegal characters and converts to lowercase.
 */
function isEmailCorrect(email) {
    if (!email || typeof email !== 'string') return "";

    // Trim whitespace and convert to lowercase
    let clean = email.trim().toLowerCase();

    // Strict Alphanumeric + Symbols regex for Emails
    // Prevents injection of characters like < > ( ) ' " ;
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    return emailRegex.test(clean)
}

async function handleRegistration (user_data) {
    try {
        if(!(isEmailCorrect(user_data.email) && isStringClean(user_data.lastname) && isStringClean(user_data.lastname) && isPasswordStrong(user_data.password)))
            throw new Error("Data are not correct.");

        const {
            public_key,
            private_key
        } = await generateRSAKeyPair();
    
        if (!public_key || !private_key){
            Swal.fire('Security issue', "Failed to generate RSA keys.", 'error');
            throw new Error();
        }
  
        const symmetric_key = await generateSymmetricKey();
        const hmac_key = await generateHMACKey();
        
        const hmac_email = await generateMAC(user_data.email, hmac_key);

        const encrypted_firstname = JSON.stringify(await encryptData(user_data.firstname, symmetric_key));
        const hmac_firstname = await generateMAC(encrypted_firstname, hmac_key);

        const encrypted_lastname = JSON.stringify(await encryptData(user_data.lastname, symmetric_key));
        const hmac_lastname = await generateMAC(encrypted_lastname, hmac_key);

        let encrypted_birthdate, hmac_birthdate, encrypted_organization, hmac_organization;
        if (user_data.birthdate && isDateCorrect(user_data.birthdate)) {
            encrypted_birthdate = JSON.stringify(await encryptData(user_data.birthdate, symmetric_key));
            hmac_birthdate = await generateMAC(encrypted_birthdate, hmac_key);
        }
        else if(user_data.organization && isStringClean(user_data.organization)) {
            encrypted_organization = JSON.stringify(await encryptData(user_data.organization, symmetric_key));
            hmac_organization = await generateMAC(encrypted_organization, hmac_key);
        }
        else {
            Swal.fire('Data format', "Missing birthdate or organization", 'error');
            throw new Error();
        }
        
        const imported_public_key = await importPublicKey(public_key, 'encrypt'); 
        const imported_private_key = await importPrivateKey(private_key, 'sign');
        
        const encrypted_signature_symmetric_key = await encryptAndSignKey(symmetric_key, imported_public_key, imported_private_key);
        const encrypted_signature_hmac_key = await encryptAndSignKey(hmac_key, imported_public_key, imported_private_key);

        const derived_key = await derivePasswordKey(user_data.password, user_data.email); 
        const encrypted_private_key = JSON.stringify(await encryptData(private_key, derived_key));
        const derived_hash_key = await deriveHashPassword(user_data.password, user_data.email);
        const hmac_private_key = await generateMAC(encrypted_private_key, derived_hash_key);
        
        var data = {
            email: user_data.email,
            hmac_email,
            firstname: encrypted_firstname,
            hmac_firstname,
            lastname: encrypted_lastname,
            hmac_lastname,
            birthdate: encrypted_birthdate,
            hmac_birthdate,
            encrypted_symmetric_key: encrypted_signature_symmetric_key.key,
            signed_symmetric_key: encrypted_signature_symmetric_key.signature,
            encrypted_hmac_key: encrypted_signature_hmac_key.key,
            signed_hmac_key: encrypted_signature_hmac_key.signature,
            public_key,
            private_key: encrypted_private_key,
            hmac_private_key
        };
        if(! user_data.organization) {
            return JSON.stringify(data);
        }

        data["organization"] = encrypted_organization;
        data["hmac_organization"] = hmac_organization;
        return JSON.stringify(data);
    } catch (error) {
        //Swal.fire('Data format', 'Your data are not correct. ' + error, 'error');
    }
}

async function handleProfile(user_data, password){
    try {

        if (!user_data.public_key){
            Swal.fire('Key Pair problem', 'Public key not found.', 'error');
            return;
        }

        if (!user_data.private_key) {
            Swal.fire('Key Pair problem', 'Private key not found.', 'error');
            return;
        }

        const enc_private_key = JSON.parse(user_data.private_key);
        const derived_key = await derivePasswordKey(password, user_data.email);
        const derived_hash_key = await deriveHashPassword(password, user_data.email);
        const is_private_key_valid = await verifyMAC(user_data.private_key, user_data.hmac_private_key, derived_hash_key);
        const decrypted_private_key =  await decryptData(enc_private_key, derived_key);
        KeyManager.setKey(decrypted_private_key, user_data.public_key);

        const imported_public_key = await importPublicKey(user_data.public_key, 'verify');
        const imported_private_key = await importPrivateKey(decrypted_private_key, 'decrypt');

        // Verify the keys
        const is_symmetric_key_valid = await verifySignatureWithPublicKey(user_data.encrypted_symmetric_key, user_data.signed_symmetric_key, imported_public_key);
        const is_hmac_key_valid = await verifySignatureWithPublicKey(user_data.encrypted_hmac_key, user_data.signed_hmac_key, imported_public_key);
        if (!is_symmetric_key_valid || !is_hmac_key_valid || !is_private_key_valid) {
            // TODO delete user with false data
            //await deleteUser(email);
            Swal.fire('Security Issue', 'Invalid user: The user\'s keys has been modified or is invalid.', 'error');
            return;
        }

        // Decrypt symmetric key
        const symmetric_key_base64 = await decryptWithPrivateKey(user_data.encrypted_symmetric_key, imported_private_key);
        const symmetric_key = await importKey(base64ToArrayBuffer(symmetric_key_base64));
        // Decrypt HMAC key
        const hmac_key_base64 = await decryptWithPrivateKey(user_data.encrypted_hmac_key, imported_private_key);
        const hmac_key = await importHmacKey(base64ToArrayBuffer(hmac_key_base64));
        
        // Verify the HMAC
        const is_firstname_valid = await verifyMAC(user_data.firstname, user_data.hmac_firstname, hmac_key);
        const is_lastname_valid = await verifyMAC(user_data.lastname, user_data.hmac_lastname, hmac_key);
        const is_email_valid = await verifyMAC(user_data.email, user_data.hmac_email, hmac_key);

        if (!is_firstname_valid || ! is_lastname_valid || !is_email_valid ) {
            //await deleteUser(email);
            Swal.fire('Invalid user: The user\'s data has been modified or is invalid.');
        }

        // Decrypt and verify user data
        const enc_firstname = JSON.parse(user_data.firstname);
        const decrypted_firstname = await decryptData(enc_firstname, symmetric_key);

        const enc_lastname = JSON.parse(user_data.lastname);
        const decrypted_lastname = await decryptData(enc_lastname, symmetric_key);

        if (user_data.organization){
            const is_organization_valid = await verifyMAC(user_data.organization, user_data.hmac_organization, hmac_key);
            const enc_organization = JSON.parse(user_data.organization);
            const decrypted_organization = await decryptData(enc_organization, symmetric_key);
            if (is_organization_valid)
                return {
                    email: user_data.email,
                    firstname: decrypted_firstname,
                    lastname: decrypted_lastname,
                    organization: decrypted_organization,
                };
            Swal.fire('Security Issue', 'Your data has been modified', 'error');
            return;
        }

        const is_birthdate_valid = await verifyMAC(user_data.birthdate, user_data.hmac_birthdate, hmac_key);
        const enc_birthdate = JSON.parse(user_data.birthdate);
        const decrypted_birthdate = await decryptData(enc_birthdate, symmetric_key);
        if (is_birthdate_valid)
            return {
                email: user_data.email,
                firstname: decrypted_firstname,
                lastname: decrypted_lastname,
                birthdate: decrypted_birthdate,
            };
        Swal.fire('Security Issue', 'Your data has been modified', 'error');
        return;

    } catch (error) {
        throw Error('Unable to decrypt data.' + error);
    }
};

/**
 * Generates a cryptographic signature for a specific action
 * @param {string} action (ex: 'delete_file')
 * @returns {Promise<string>} base64 signature
 */
async function signLogAction(action) {
    try {
        const userKeys = KeyManager.getKey();
        if(!userKeys._privateKey) throw new Error("No private key found for logging.");

        const signPriv = await importPrivateKey(userKeys._privateKey, 'sign');
        const timestamp = Date.now().toString();
        const payload = action + "|" + timestamp;
        const signature = await signWithPrivateKey(payload, signPriv);

        return {
            signature: signature,
            timestamp: timestamp
        };
    } catch (e) {
        console.error("Log signing failed:", e);
        return null;
    }
}