const SharingManager = {
    targetFolderId: null,

    setTargetFolder: function(fid) {
        this.targetFolderId = fid;
        this.loadShares();
    },

    loadShares: async function() {
        const signed_data = await signLogAction("SHARE");
        $.ajax({
            url: "get_shared",
            type: "post",
            data: {'user_id': DashboardManager.userId, 'folder_id': this.targetFolderId, 'action': "SHARE", 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp},
            headers: {'X-CSRFToken': DashboardManager.csrfToken},
            success: (data) => {
                const container = document.getElementById("shared-container");
                container.innerHTML = "";
                data.forEach((item, i) => {
                    container.innerHTML += `
                        <tr>
                            <td>${i+1}</td>
                            <td>${item.email}</td>
                            <td><button class="btn btn-danger btn-sm" onclick="SharingManager.revoke(${item.id})">Revoke</button></td>
                        </tr>
                    `;
                });
            }
        });
    },

    share: async function() {
        const email = $("#share_emailbox").val();
        if(!email) { UiManager.showToast('warning', 'Select a doctor'); return; }
        
        const folderId = this.targetFolderId;
        if(!folderId) return;

        try {
            UiManager.showToast('info', 'Generating Secure Keys for Doctor...');

            const userKeys = await KeyManager.getKey();
            if(!userKeys._privateKey) { UiManager.showToast('error', 'Please relogin'); return; }

            const patientPriv = await importPrivateKey(userKeys._privateKey, 'decrypt');
            const patientPub = await importPublicKey(userKeys._publicKey, 'verify');
            const patientSignPriv = await importPrivateKey(userKeys._privateKey, 'sign');

            let signed_data = await signLogAction("PROVIDE");
            const meta = await $.post('get_folder_metadata', {
                'folder_id': folderId, 
                'csrfmiddlewaretoken': DashboardManager.csrfToken,
                'action': "PROVIDE",
                'client_sign': signed_data.signature, 
                'timestamp': signed_data.timestamp
            });
            if(meta.error) throw new Error(meta.error);

            const folderKey = await decryptAndVerifyKey(meta.enc_sym, meta.sig_sym, patientPub, patientPriv);
            const hmacKey = await decryptAndVerifyKey(meta.enc_hmac, meta.sig_hmac, patientPub, patientPriv);

            signed_data = await signLogAction("AUTH");
            const docData = await $.post('get_public_key', {
                'email': email,
                'csrfmiddlewaretoken': DashboardManager.csrfToken,
                'action': "AUTH",
                'client_sign': signed_data.signature, 
                'timestamp': signed_data.timestamp
            });
            if(docData.error) throw new Error(docData.error);
            
            const doctorPub = await importPublicKey(docData.public_key, 'encrypt');
            const secureAES = await encryptAndSignKey(folderKey, doctorPub, patientSignPriv);
            const secureHMAC = await encryptAndSignKey(hmacKey, doctorPub, patientSignPriv);

            signed_data = await signLogAction("SHARE");
            $.ajax({
                url: 'check_share',
                type: 'post',
                data: {
                    'user_id': DashboardManager.userId, 
                    'folder_id': folderId, 
                    'doctor': email, 
                    'status': 'authorized',
                    'encrypted_symmetric_key': secureAES.key,
                    'signed_symmetric_key': secureAES.signature,
                    'encrypted_hmac_key': secureHMAC.key,
                    'signed_hmac_key': secureHMAC.signature,
                    'action': "SHARE",
                    'client_sign': signed_data.signature, 
                    'timestamp': signed_data.timestamp
                },
                headers: {'X-CSRFToken': DashboardManager.csrfToken},
                success: (data) => {
                    if(data.status) {
                        UiManager.showToast('success', `Shared with ${email}`);
                        if(typeof DashboardManager !== 'undefined') DashboardManager.loadFolders();
                        $("#share_emailbox").val('');
                        this.loadShares();
                    } else {
                        UiManager.showToast('error', data.error);
                    }
                }
            });
        } catch (e) {
            console.error(e);
            UiManager.showToast('error', 'Sharing Failed: ' + e.message);
        }
    },

    revoke: async function(id) {
        const signed_data = await signLogAction("SHARE");
        $.ajax({
            url: 'revoke_share',
            type: 'post',
            data: {'id': id, 'action': "SHARE", 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp},
            headers: {'X-CSRFToken': DashboardManager.csrfToken},
            success: (data) => {
                if(data.status) {
                    UiManager.showToast('info', 'Access revoked');
                    this.loadShares();
                    
                    if(typeof DashboardManager !== 'undefined') DashboardManager.loadFolders();
                }
            }
        });
    }
};