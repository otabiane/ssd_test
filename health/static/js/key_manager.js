const dbName = "AuthStore";

const KeyManager = (function() {
    let _expiryTimer = null;
    let _memoryStore = {
        privateKey: null,
        publicKey: null,
    };

    return {
        setKey: function(privKey, pubKey) {
            _memoryStore.privateKey = privKey;
            _memoryStore.publicKey = pubKey;

            if (_expiryTimer) clearTimeout(_expiryTimer);

            _expiryTimer = setTimeout(() => {
                this.clear();
                alert("Session expired. Private key has been cleared.");
            }, 10 * 60 * 1000); // 10minutes lifetime
        },

        getKey: function() {
            return {
                _privateKey: _memoryStore.privateKey, 
                _publicKey: _memoryStore.publicKey
            };
        },

        clear: function() {
            _memoryStore = { privateKey: null, publicKey: null };
            _expiryTimer = null;
        }
    };
})();