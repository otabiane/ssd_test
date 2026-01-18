const DashboardManager = {
    userId: null,
    csrfToken: null,
    currentFolderId: null,
    isDoctor: false,

    init: function(uid, token, isDoctor=false) {
        this.userId = uid;
        this.csrfToken = token;
        this.isDoctor = isDoctor;
        
        $('#btn-save-folder').on('click', () => this.saveFolder());
    },

    // --- FOLDERS 
    loadFolders: async function(is_option=true) {
        this.currentFolderId = null;
        const signed_data = await signLogAction("PROVIDE");
        $.ajax({
            url: "folder_provider/",
            type: "post",
            data: {'user_id': this.userId, 'action': "PROVIDE", 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp},
            headers: {'X-CSRFToken': this.csrfToken},
            success: (data) => this.renderFolders(data, is_option, false)
        });
    },

    loadSharedFolders: async function() {
        this.currentFolderId = null;
        const signed_data = await signLogAction("PROVIDE");
        $.ajax({
            url: "shared_folder_provider/",
            type: "post",
            data: {'user_id': this.userId, 'action': "PROVIDE", 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp},
            headers: {'X-CSRFToken': this.csrfToken},
            success: (data) => this.renderFolders(data, false, true)
        });
    },

    renderFolders: async function(data, is_option, is_shared) {
        const container = document.getElementById("folder-container");
        if(!container) return;
        container.innerHTML = "";

        if(data.length === 0) {
            container.innerHTML = "<tr><td colspan='5' class='text-center text-muted'>No records found.</td></tr>";
            return;
        }

        data.forEach(async (folder, i) => {
            const userKeys = KeyManager.getKey();
            if(!userKeys._publicKey || !userKeys._privateKey) {
                UiManager.showToast('error', 'Keys missing! Please login again.');
                return;
            }

            let imported_public_key = await importPublicKey(userKeys._publicKey, 'verify');
            const imported_private_key = await importPrivateKey(userKeys._privateKey, 'decrypt');
            
            const signed_data = await signLogAction("PROVIDE");
            const meta = await $.post('get_folder_metadata', {
                'folder_id': folder.id, 
                'csrfmiddlewaretoken': this.csrfToken,
                'action': "PROVIDE",
                'client_sign': signed_data.signature,
                'timestamp': signed_data.timestamp
            });
            
            if (meta.error) throw new Error(meta.error);

            if(meta.owner_public_key) {
                imported_public_key = await importPublicKey(meta.owner_public_key, 'verify');
            }
            // Verify the keys
            const is_symmetric_key_valid = await verifySignatureWithPublicKey(meta.enc_sym, meta.sig_sym, imported_public_key);
            const is_hmac_key_valid = await verifySignatureWithPublicKey(meta.enc_hmac, meta.sig_hmac, imported_public_key);
            if (!is_symmetric_key_valid || !is_hmac_key_valid ) {
                const signed_data = await signLogAction("MANAGE");
                $.ajax({
                    url: "delete_folder",
                    type: "post",
                    data: {'user_id': this.userId, 'folder_id': folder.id, 'action': "MANAGE", 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp},
                    headers: {'X-CSRFToken': this.csrfToken},
                    success: (data) => {
                        if(data.Status) {
                            Swal.fire('Deleted!', 'Folder has been deleted. The folder has been corrupted!', 'error');
                        }
                    }
                });
                return;
            }

            // Decrypt symmetric key
            const symmetric_key_base64 = await decryptWithPrivateKey(meta.enc_sym, imported_private_key);
            const symmetric_key = await importKey(base64ToArrayBuffer(symmetric_key_base64));
            // Decrypt HMAC key
            const hmac_key_base64 = await decryptWithPrivateKey(meta.enc_hmac, imported_private_key);
            const hmac_key = await importHmacKey(base64ToArrayBuffer(hmac_key_base64));
            
            // Verify the HMAC
            const is_name_valid = await verifyMAC(folder.name, folder.hmac_name, hmac_key);
            const is_date_valid = await verifyMAC(folder.appointment_date, folder.hmac_appointment_date, hmac_key);

            if (!is_name_valid || ! is_date_valid) {
                const signed_data = await signLogAction("MANAGE");
                $.ajax({
                    url: "delete_folder",
                    type: "post",
                    data: {'user_id': this.userId, 'folder_id': folder.id, 'action': "MANAGE", 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp},
                    headers: {'X-CSRFToken': this.csrfToken},
                    success: (data) => {
                        if(data.Status) {
                            Swal.fire('Security issue', 'Folder has been deleted. The folder has been corrupted!', 'error');
                        }
                    }
                });
                return;
            }

            // Decrypt and verify user data
            const enc_name = JSON.parse(folder.name);
            const decrypted_name = await decryptData(enc_name, symmetric_key);

            const enc_date = JSON.parse(folder.appointment_date);
            const decrypted_date = await decryptData(enc_date, symmetric_key);

            const row = document.createElement("tr");
            let doctorsHtml = "<i class='fas text-black'>No Appointed Doctor</i>";

            if(is_shared) {  
                doctorsHtml = `<b>Owner:</b> ${folder.user}`;
            } else {
                if(folder.doctors && folder.doctors.length > 0) {
                    doctorsHtml = "<ul>" + folder.doctors.map(d => `
                        <li>${d.email} <button class='btn btn-danger btn-sm m-1' onclick="SharingManager.revoke(${d.id})">Revoke</button></li>
                    `).join('') + "</ul>";
                }
            }

            let optionsHtml = "";
            if(is_option && !is_shared) {
                optionsHtml = `
                    <button class="btn btn-success m-2" data-toggle="modal" data-target="#shareModal" data-folder-id="${folder.id}" onclick="SharingManager.setTargetFolder(${folder.id})">
                        <i class='fas fa-share text-white'></i>
                    </button>
                    <button class="btn btn-danger m-2" onclick="DashboardManager.deleteFolder(${folder.id}, this)">
                        <i class='fas fa-trash text-white'></i>
                    </button>
                `;
            }
            optionsHtml += `<button class="btn bg-dark m-2" onclick='DashboardManager.downloadFolderZip(${folder.id}, ${folder.name})'><i class='fas fa-download text-white'></i></button>`;

            const dest = is_option ? '/dashboard' : '/shared_dashboard';
            const targetUrl = `${dest}?folder_id=${folder.id}`;

            row.innerHTML = `
                <input type="hidden" value="${folder.id}">
                <td>${i+1}</td>
                <td style="cursor:pointer; color:#007bff; font-weight:bold" 
                    onclick="htmx.ajax('GET', '${targetUrl}', {target: 'body', pushUrl: true})">
                    <i class="fas fa-folder"></i> ${decrypted_name}
                </td>
                <td>${folder.created_at}</td>
                <td>${decrypted_date}</td>
                <td>${doctorsHtml}</td>
                <td>${optionsHtml}</td>
            `;
            container.appendChild(row);
        });
    },

    downloadFolderZip: async function(folderId, folderName) {
        try {
            UiManager.showToast('info', 'Downloading...');

            const userKeys = await KeyManager.getKey();
            if(!userKeys._privateKey) {
                window.location.href = "/logout";
                Swal.fire('Timeout', 'Keys locked. Please relogin.');
                return;
            }
            const importedPriv = await importPrivateKey(userKeys._privateKey, 'decrypt');
            let importedPub = await importPublicKey(userKeys._publicKey, 'verify');

            const providerUrl = this.isDoctor ? 'shared_file_provider/' : 'file_provider/';
            const signed_data = await signLogAction("PROVIDE");

            const [meta, files] = await Promise.all([
                $.post('get_folder_metadata', {'folder_id': folderId, 'csrfmiddlewaretoken': this.csrfToken, 'action': "PROVIDE", 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp}),
                $.post(providerUrl, {'user_id': this.userId, 'folder_id': folderId, 'csrfmiddlewaretoken': this.csrfToken, 'action': 'PROVIDE', 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp})
            ]);

            if (meta.error) throw new Error(meta.error);
            if (files.length === 0) { UiManager.showToast('warning', 'Folder is empty'); return; }

            if(meta.owner_public_key) {
                importedPub = await importPublicKey(meta.owner_public_key, 'verify');
            }

            const folderKey = await decryptAndVerifyKey(meta.enc_sym, meta.sig_sym, importedPub, importedPriv);

            const zip = new JSZip();

            const decrypted_name = await decryptData(folderName, folderKey);
            const root = zip.folder(decrypted_name);
            UiManager.showToast('info', `Decrypting ${files.length} files...`);

            for (let i = 0; i < files.length; i++) {
                const file = files[i];
                
                try {
                    let realName = "Unknown_File";
                    try { realName = await decryptFilename(file.title, folderKey); } catch(e){}

                    const signed_dl = await signLogAction("DOWNLOAD")
                    const response = await fetch(`/file_download?era=${file.link}&iera=${this.userId}&action=DOWNLOAD&client_sign=${encodeURIComponent(signed_dl.signature)}&timestamp=${signed_dl.timestamp}`);
                    if (!response.ok) throw new Error("Download failed");
                    
                    const encryptedBuffer = await response.arrayBuffer();
                    const decryptedBytes = await decryptImage(new Uint8Array(encryptedBuffer), folderKey);

                    root.file(realName, decryptedBytes);                    
                } catch (err) {
                    console.error(`Skipping file ${file.id}`, err);
                }
            }

            UiManager.showToast('info', 'Compressing...');
            const zipContent = await zip.generateAsync({type:"blob"});

            const url = window.URL.createObjectURL(zipContent);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = `${decrypted_name}.zip`;
            document.body.appendChild(a);

            a.click();
            
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);

            UiManager.showToast('success', 'Zip Downloaded');
        } catch (e) {
            console.error(e);
            UiManager.showToast('error', 'Zip Failed: ' + e.message);
        }
    },

    saveFolder: async function() {
        const name = $("#foldernamebox").val();
        const date = $("#folderdatebox").val();
        if (!name) { UiManager.showToast('error', 'Please enter a name!'); return; }
        if (!date) { UiManager.showToast('error', 'Please enter an appointment date!'); return; }
        if (!isStringClean(name)) { UiManager.showToast('string format', 'Please enter a valid name!'); return; }
        if (!isDateCorrect(date)) { UiManager.showToast('date', 'Please enter a correct appointment date!'); return; }

        try {
            const userKeys = KeyManager.getKey();
            if(!userKeys._publicKey || !userKeys._privateKey) {
                UiManager.showToast('error', 'Keys missing! Please login again.');
                return;
            }

            const importedPub = await importPublicKey(userKeys._publicKey, 'encrypt');
            const importedPriv = await importPrivateKey(userKeys._privateKey, 'sign');

            const folderAESKey = await generateSymmetricKey(); // use for encrypt the file
            const folderHMACKey = await generateHMACKey(); // for signing files

            const secureAES = await encryptAndSignKey(folderAESKey, importedPub, importedPriv);
            const secureHMAC = await encryptAndSignKey(folderHMACKey, importedPub, importedPriv);

            const encrypted_name = JSON.stringify(await encryptData(name, folderAESKey)); 
            const hmac_name = await generateMAC(encrypted_name, folderHMACKey);

            const encrypted_date = JSON.stringify(await encryptData(date, folderAESKey));
            const hmac_date = await generateMAC(encrypted_date, folderHMACKey);

            const signed_data = await signLogAction("MANAGE");
            $.ajax({
                url: "save_folder",
                type: "post",
                data: {
                    'name': encrypted_name,
                    'hmac_name': hmac_name,
                    'date': encrypted_date,
                    'hmac_date': hmac_date,
                    'encrypted_symmetric_key': secureAES.key,
                    'signed_symmetric_key': secureAES.signature,
                    'encrypted_hmac_key': secureHMAC.key,
                    'signed_hmac_key': secureHMAC.signature,

                    'action': "MANAGE",
                    'client_sign': signed_data.signature, 
                    'timestamp': signed_data.timestamp
                },
                headers: {'X-CSRFToken': this.csrfToken},
                success: (data) => {
                    if(data.status) {
                        UiManager.showToast('success', 'Folder created');
                        $('#folderModal').modal('hide');
                        this.loadFolders();
                    } else {
                        UiManager.showToast('warning', 'Error: ' + data.error);
                    }
                },
                error: (err) => {
                    UiManager.showToast('error', 'Server Error: ' + err);
                }
            });
        } catch (e) {
            UiManager.showToast('error', 'Encryption error: ' + e);
        }

    },

    deleteFolder: function(id, btnElement) {
        Swal.fire({
            title: 'Are you sure?', text: "You won't be able to revert this!", icon: 'warning',
            showCancelButton: true, confirmButtonText: 'Yes, delete it!'
        }).then(async (result) => {
            if (result.value) {
                const signed_data = await signLogAction("MANAGE");
                $.ajax({
                    url: "delete_folder",
                    type: "post",
                    data: {'user_id': this.userId, 'folder_id': id, 'action': "MANAGE", 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp},
                    headers: {'X-CSRFToken': this.csrfToken},
                    success: (data) => {
                        if(data.Status) {
                            $(btnElement).closest('tr').remove();
                            Swal.fire('Deleted!', 'Folder has been deleted.', 'success');
                        }
                    }
                });
            }
        });
    },

    // --- FILES 
    loadFiles: async function(folderId) {
        this.currentFolderId = folderId;

        const container = document.getElementById("files-container");
        if(container) container.innerHTML = "<div class='col-12 text-center p-5'><i class='fas fa-spinner fa-spin fa-2x'></i><br>Unlocking Secure Folder...</div>";

        try {
            const userKeys = await KeyManager.getKey();
            if (!userKeys._privateKey) {
                //container.innerHTML = "<div class='text-danger p-5'>Keys locked. Please relogin.</div>";
                Swal.fire('Timeout', 'Keys locked. Please relogin.');
                window.location.href = "/logout";
                return;
            }
            const importedPriv = await importPrivateKey(userKeys._privateKey, 'decrypt');
            let importedPub = await importPublicKey(userKeys._publicKey, 'verify');

            const providerUrl = this.isDoctor ? 'shared_file_provider/' : 'file_provider/';
            const signed_data = await signLogAction("PROVIDE");

            const [meta, files] = await Promise.all([
                $.post('get_folder_metadata', {'folder_id': folderId, 'csrfmiddlewaretoken': this.csrfToken, 'action': "PROVIDE", 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp}),
                $.post(providerUrl, {'user_id': this.userId, 'folder_id': folderId, 'csrfmiddlewaretoken': this.csrfToken, 'action': "PROVIDE", 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp}) // Ensure we use AJAX
            ]);

            if(meta.owner_public_key) {
                importedPub = await importPublicKey(meta.owner_public_key, 'verify');
            }
            
            // Verify the keys
            const is_symmetric_key_valid = await verifySignatureWithPublicKey(meta.enc_sym, meta.sig_sym, importedPub);
            const is_hmac_key_valid = await verifySignatureWithPublicKey(meta.enc_hmac, meta.sig_hmac, importedPub);
            if(!is_symmetric_key_valid || !is_hmac_key_valid) {
                const signed_data = await signLogAction("MANAGE");
                $.ajax({
                    url: "delete_folder",
                    type: "post",
                    data: {'user_id': this.userId, 'folder_id': folderId, 'action': "MANAGE", 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp},
                    headers: {'X-CSRFToken': this.csrfToken},
                    success: (data) => {
                        if(data.Status) {
                            Swal.fire('Deleted!', 'Folder has been deleted. The keys folder has been corrupted!', 'error');
                        }
                    }
                });
                return;
            }
            // Decrypt symmetric key
            const symmetric_key_base64 = await decryptWithPrivateKey(meta.enc_sym, importedPriv);
            const folderKey = await importKey(base64ToArrayBuffer(symmetric_key_base64));
            // Decrypt HMAC key
            const hmac_key_base64 = await decryptWithPrivateKey(meta.enc_hmac, importedPriv);
            const hmac_key = await importHmacKey(base64ToArrayBuffer(hmac_key_base64));
            
            const displayFiles = [];
            for (let i = 0; i < files.length; i++) {
                const file = files[i];
                let realName = "Unknown";

                if(!file.blob_url){
                    const is_title_valid = await verifyMAC(file.title, file.hmac_title, hmac_key);
                    const is_size_valid = await verifyMAC(file.size, file.hmac_size, hmac_key);

                    const signed_dl = await signLogAction("DOWNLOAD")
                    const response = await fetch(`/file_download?era=${file.link}&iera=${this.userId}&action=DOWNLOAD&client_sign=${encodeURIComponent(signed_dl.signature)}&timestamp=${signed_dl.timestamp}`);
                    if (!response.ok) throw new Error("Download failed");
                    
                    const encryptedBuffer = await response.arrayBuffer();
                    
                    if(!is_title_valid || !is_size_valid ) {
                        const signed_data = await signLogAction("MANAGE");
                        $.ajax({
                            url: "delete", type: "post",
                            data: {'user_id': this.userId, 'file_id': file.id, 'file_link': file.link, 'action': "MANAGE", 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp},
                            headers: {'X-CSRFToken': this.csrfToken},
                            success: (data) => {
                                if(data.Status) {
                                    UiManager.showToast('Security Issue', 'File deleted, the keys are corrupted.');
                                }
                            }
                        });
                    }
                } else {
                    const signed_data = await signLogAction("AUTH");
                    const public_key = await $.post('get_public_key', {
                        'email': file.uploaded_by__email, 
                        'csrfmiddlewaretoken': this.csrfToken, 
                        'action': "AUTH", 
                        'client_sign': signed_data.signature, 
                        'timestamp': signed_data.timestamp
                    });
                    importedPub = await importPublicKey(public_key.public_key, 'verify');
                    const is_title_valid = await verifySignatureWithPublicKey(file.title, file.signed_title, importedPub);
                    const is_size_valid = await verifySignatureWithPublicKey(file.size, file.signed_size, importedPub);

                    if(!is_title_valid || !is_size_valid) {
                        const signed_data = await signLogAction("MANAGE");
                        $.ajax({
                            url: "delete_file_doctor", type: "post",
                            data: {'user_id': this.userId, 'file_id': file.id},
                            headers: {'X-CSRFToken': this.csrfToken, 'action': "MANAGE", 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp},
                            success: (data) => {
                                if(data.Status) {
                                    UiManager.showToast('Security Issue', 'File deleted, the keys are corrupted.');
                                }
                            }
                        });
                    }

                    const signed_dl = await signLogAction("DOWNLOAD")
                    const response = await fetch(`/file_download?era=${file.blob_url}&iera=${this.userId}&action=DOWNLOAD&client_sign=${encodeURIComponent(signed_dl.signature)}&timestamp=${signed_dl.timestamp}`);
                    if (!response.ok) throw new Error("Download failed");
                    
                    const encryptedBuffer = await response.arrayBuffer();
                    const decryptedBytes = await decryptImage(new Uint8Array(encryptedBuffer), folderKey);

                    // Convert decrypted bytes to a viewable Blob URL
                    const fileBlob = new Blob([decryptedBytes], { type: 'application/octet-stream' });
                    const is_blob_valid = await verifySignatureWithPublicKey(new Blob([encryptedBuffer], { type: 'application/octet-stream' }), file.signed_blob, importedPub);
                    file.viewUrl = window.URL.createObjectURL(fileBlob);
                }
                const enc_size = JSON.parse(file.size);
                const decrypted_size = await decryptData(enc_size, folderKey);

                try {
                    realName = await decryptFilename(file.title, folderKey);
                } catch (err) {
                    console.error("Failed to decrypt name for file " + file.id);
                    realName = "Decryption Error";
                }
                file.realName = realName;
                file.size = parseInt(decrypted_size);
                displayFiles.push(file);
            }

            this.renderFiles(displayFiles, folderId);
        } catch (e) {
            console.error(e);
            if(container) container.innerHTML = `<div class='text-danger p-5'>Decryption Failed: ${e.message}</div>`;
        }
    },

    renderFiles: async function(data, folderId) {
        const container = document.getElementById("files-container");
        const container2 = document.getElementById("folder-container");
        if(!container || !container2) return;
        container.innerHTML = "";
        container2.innerHTML = "";
        let keys = data.filter(x => {return x.blob_url}).map(x => {return x.file__id});

        if(data.length === 0) {
            container.innerHTML = "<div class='text-muted p-5'>No files in this folder.</div>";
            return;
        }

        data.forEach(async (file) => {
            if(!file.blob_url) {
                const ext = file.realName.split('.').pop().toUpperCase();

                const card = document.createElement("div");
                card.className = "col-md-2 m-2 text-center p-0 rounded bg-light";
                
                let preview = `<div class="p-4 bg-white border-bottom"><h3>${ext}</h3></div>`;
                const displayName = file.realName.length > 20 ? file.realName.substring(0,15)+'...' : file.realName;

                const isShared = window.location.pathname.includes('shared');
                let deleteBtn = "";
                if(!this.isDoctor && !isShared) {
                    deleteBtn = `
                    <button class="btn btn-light rounded-0 text-danger" onclick="DashboardManager.deleteFile(${file.id}, this)">
                        <i class='fas fa-trash'></i>
                    </button>`;
                }
                if(this.isDoctor && !keys.includes(file.id) && !file.file__id) {
                    deleteBtn = `
                    <button class="btn btn-light rounded-0 text-danger" onclick="DashboardManager.deleteFileDoctor(${file.id}, '${file.realName}')">
                        <i class='fas fa-trash'></i>
                    </button>`;
                }

                card.innerHTML = `
                    ${preview}
                    <div class="font-weight-bold bg-info text-white p-2 notch">${displayName}</div>
                    <div class="text-muted p-1 d-flex justify-content-between small">
                        <span>${file.upload_date}</span>
                        <span>${UiManager.bytesToSize(file.size)}</span>
                    </div>
                    <div class="w-100 btn-group">
                        ${deleteBtn}
                        <button class="btn btn-dark rounded-0 text-white" 
                                onclick="DashboardManager.downloadEncrypted('${file.link}', '${file.realName}', ${folderId})">
                            <i class='fas fa-download'></i>
                        </button>
                    </div>
                `;
                container.appendChild(card);
            } else {
                const card = document.createElement("tr");
                if (file.size == 0) {
                    file.text = `Want to delete file <b>${file.realName}</b>`;
                } else  {
                    file.text = `Want to add <b> ${file.realName}</b>`;
                }
 
                card.innerHTML = `
                <td>${file.id + 1}</td>
                <td>${file.text}</td>
                <td>${file.uploaded_by__email}</td>
                `;
                if(!this.isDoctor) {
                    card.innerHTML += `
                    <td>
                        <button class="btn btn-success btn-sm" onclick="DashboardManager.approveFile(${file.id}, ${this.currentFolderId})">
                            <i class="fas fa-check"></i>
                        </button>
                    </td>
                    <td>
                        <button class="btn btn-danger btn-sm" onclick="DashboardManager.declineFile(${file.id}, ${this.currentFolderId})">
                            <i class="fas fa-times"></i>
                        </button>
                    </td>
                    `;
                }
                if(file.size) {
                    card.innerHTML += `<td>
                                            <a href="${file.viewUrl}" download="${file.realName}" class="btn btn-info btn-sm">View</a>
                                        </td>`;
                }
                container2.appendChild(card);
            }
        });
    },

    declineFile: async function(fileId, folderId){
        const signed_data = await signLogAction("MANAGE");
        $.ajax({
            url: "delete_file_doctor", type: "post",
            data: {'user_id': this.userId, 'file_id': fileId, 'folder_id': folderId, 'action': "MANAGE", 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp},
            headers: {'X-CSRFToken': this.csrfToken},
            success: (data) => {
                if(data.Status) {
                    UiManager.showToast('success', 'File request declined!');
                    this.loadFiles(folderId);
                }
            }
        });
    },

    //approve file version
    approveFile: async function(fileId, folderId) {
        try {
            //Get Keys and Metadata
            const userKeys = await KeyManager.getKey();
            const importedPriv = await importPrivateKey(userKeys._privateKey, 'decrypt');
            let signed_data = await signLogAction("PROVIDE");
            const meta = await $.post('get_folder_metadata', {
                'folder_id': this.currentFolderId, 
                'csrfmiddlewaretoken': this.csrfToken,
                'action': "PROVIDE",
                'client_sign': signed_data.signature, 
                'timestamp': signed_data.timestamp
            });

            signed_data = await signLogAction("MANAGE");
            let fileVersion = await $.post('get_file_version', {
                'folder_id': folderId, 
                'file_id': fileId,
                'csrfmiddlewaretoken': this.csrfToken,
                'action': "MANAGE",
                'client_sign': signed_data.signature, 
                'timestamp': signed_data.timestamp
            });
            fileVersion = fileVersion.data;
            // Decrypt Keys
            const symKeyBase64 = await decryptWithPrivateKey(meta.enc_sym, importedPriv);
            const folderKey = await importKey(base64ToArrayBuffer(symKeyBase64));
            const hmacKeyBase64 = await decryptWithPrivateKey(meta.enc_hmac, importedPriv);
            const hmac_key = await importHmacKey(base64ToArrayBuffer(hmacKeyBase64));

            // Download the actual encrypted data
            const signed_dl = await signLogAction("DOWNLOAD")
            const response = await fetch(`/file_download?era=${fileVersion.blob_url}&iera=${this.userId}&action=DOWNLOAD&client_sign=${encodeURIComponent(signed_dl.signature)}&timestamp=${signed_dl.timestamp}`);
            const encryptedBlob = await response.blob();

            // Generate Patient-style HMACs (converting Doctor proposition to Patient file)
            const hmacName = await generateMAC(fileVersion.title, hmac_key);
            const hmacBlob = await generateMAC(encryptedBlob, hmac_key);
            const hmacSize = await generateMAC(fileVersion.size, hmac_key);

            const enc_size = JSON.parse(fileVersion.size);
            const decrypted_size = await decryptData(enc_size, folderKey);

            if(decrypted_size == 0) {
                const signed_data = await signLogAction("MANAGE");
                $.ajax({
                    url: "delete",
                    type: "post",
                    data: {'user_id': this.userId, 'file_id': fileVersion.file, 'action': "MANAGE", 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp},
                    headers: {'X-CSRFToken': this.csrfToken},
                    success: (data) => {
                        if(data.Status) {
                            this.loadFiles(folderId); 
                            Swal.fire('Deleted!', 'file has been deleted.', 'error');
                        }

                    }
                });
                return;
            }
            // Build FormData
            const formData = new FormData();
            formData.append('parent_id', this.currentFolderId);
            formData.append('file_id_0', fileVersion.file_id); // The original file entry to update
            formData.append('file_0', encryptedBlob, fileVersion.title);
            formData.append('size_0', fileVersion.size);
            formData.append('hmac_name_0', hmacName);
            formData.append('hmac_blob_0', hmacBlob);
            formData.append('hmac_size_0', hmacSize);
            formData.append('file_count', 1);
            formData.append('csrfmiddlewaretoken', this.csrfToken);
            formData.append('action', "MANAGE");
            signed_data = await signLogAction("MANAGE");
            formData.append('client_sign', signed_data.signature);
            formData.append('timestamp', signed_data.timestamp);

            // UPLOAD and then DELETE the proposition on success
            $.ajax({
                url: 'upload_files', // This saves it as a permanent file
                type: 'POST',
                data: formData,
                processData: false,
                contentType: false,
                success: async(data) => {
                    if (data.status === 'success') {
                        let response = await $.post('delete_file_version', {
                            'file_id': fileVersion.file_id,
                            'csrfmiddlewaretoken': this.csrfToken,
                            'action': "MANAGE",
                            'client_sign': signed_data.signature,
                            'timestamp': signed_data.timestamp
                        });
                        if (response.Status){
                            this.loadFiles(folderId); 
                            Swal.fire('Approved!', 'The file has been updated.', 'success');
                        }
                    }
                }
            });

        } catch (e) {
            console.error(e);
            UiManager.showToast('error', 'Approval failed: ' + e.message);
        }
    },

    downloadEncrypted: async function(link, filename, folderId) {
        try {
            UiManager.showToast('info', 'Downloading...');

            const userKeys = await KeyManager.getKey();
            const importedPriv = await importPrivateKey(userKeys._privateKey, 'decrypt');
            let importedPub = await importPublicKey(userKeys._publicKey, 'verify');

            const signed_data = await signLogAction("PROVIDE");
            const meta = await $.post('get_folder_metadata', {
                'folder_id': folderId, 
                'csrfmiddlewaretoken': this.csrfToken,
                'action': "PROVIDE",
                'client_sign': signed_data.signature, 
                'timestamp': signed_data.timestamp
            });
            
            if (meta.error) throw new Error(meta.error);

            if(meta.owner_public_key) {
                importedPub = await importPublicKey(meta.owner_public_key, 'verify');
            }

            const folderKey = await decryptAndVerifyKey(
                meta.enc_sym, 
                meta.sig_sym, 
                importedPub, 
                importedPriv
            );

            const signed_dl = await signLogAction("DOWNLOAD")
            const response = await fetch(`/file_download?era=${link}&iera=${this.userId}&action=DOWNLOAD&client_sign=${encodeURIComponent(signed_dl.signature)}&timestamp=${signed_dl.timestamp}`);
            if (!response.ok) throw new Error("Network download failed");
            
            const encryptedBlob = await response.blob();
            const encryptedBuffer = await encryptedBlob.arrayBuffer();
            const decryptedBytes = await decryptImage(new Uint8Array(encryptedBuffer), folderKey);

            const blob = new Blob([decryptedBytes]);
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            
            window.URL.revokeObjectURL(url);
            UiManager.showToast('success', 'File Decrypted');
        } catch (e) {
            console.error(e);
            UiManager.showToast('error', 'Download Failed: ' + e.message);
        }
    },

    deleteFile: function(fileId, btnElement) {
        Swal.fire({
            title: 'Delete File?', icon: 'warning', showCancelButton: true, confirmButtonText: 'Yes'
        }).then(async (result) => {
            if(result.value) {
                const signed_data = await signLogAction("MANAGE");
                $.ajax({
                    url: "delete", type: "post",
                    data: {
                        'user_id': this.userId, 
                        'file_id': fileId,
                        'action': "MANAGE",
                        'client_sign': signed_data.signature, 
                        'timestamp': signed_data.timestamp
                    },
                    headers: {'X-CSRFToken': this.csrfToken},
                    success: (data) => {
                        if(data.Status) {
                            $(btnElement).closest('.col-md-2').remove();
                            UiManager.showToast('success', 'File deleted');
                        }
                    }
                });
            }
        });
    },

    deleteFileDoctor: async function(fileId, fileName) {
        Swal.fire({
            title: 'Delete File?', icon: 'warning', showCancelButton: true, confirmButtonText: 'Yes'
        }).then(async (result) => {
            if(result.value) {
                const folderId = this.currentFolderId;
                if (!folderId) { UiManager.showToast('error', 'Folder not found'); return; }
                try {
                    UiManager.showToast('info', 'Starting Encryption...');

                    const userKeys = await KeyManager.getKey();
                    let importedPriv = await importPrivateKey(userKeys._privateKey, 'decrypt');
                    let importedPub = await importPublicKey(userKeys._publicKey, 'verify');

                    let signed_data = await signLogAction("PROVIDE");
                    const meta = await $.post('get_folder_metadata', {
                        'folder_id': folderId, 
                        'csrfmiddlewaretoken': this.csrfToken,
                        'action': "PROVIDE",
                        'client_sign': signed_data.signature, 
                        'timestamp': signed_data.timestamp
                    });

                    if (meta.error) throw new Error(meta.error);
                    if (meta.owner_public_key) importedPub = await importPublicKey(meta.owner_public_key, 'verify');
                    
                    // Verify the keys
                    const is_symmetric_key_valid = await verifySignatureWithPublicKey(meta.enc_sym, meta.sig_sym, importedPub);
                    if(!is_symmetric_key_valid) {
                        Swal.fire('Deleted!', 'The keys folder has been corrupted!', 'error');
                        return;
                    }
                    // Decrypt symmetric key
                    const symmetric_key_base64 = await decryptWithPrivateKey(meta.enc_sym, importedPriv);
                    const folderKey = await importKey(base64ToArrayBuffer(symmetric_key_base64));

                    const formData = new FormData();
                    formData.append('parent_id', folderId);
                    formData.append('csrfmiddlewaretoken', this.csrfToken);

                    const dummyBlob = new Blob([''], {type: 'text/plain'});
                    const encryptedBytes = await encryptImage(dummyBlob, folderKey); 
                    const encryptedBlob = new Blob([encryptedBytes], {type: 'application/octet-stream'});
                    const secureName = await encryptFilename(fileName, folderKey);
                    const encryptedSize = JSON.stringify(await encryptData(String(0), folderKey));

                    importedPriv = await importPrivateKey(userKeys._privateKey, 'sign');
                    const signedName = await signWithPrivateKey(secureName, importedPriv);
                    const signedBlob = await signWithPrivateKey(encryptedBlob, importedPriv);
                    const signedSize = await signWithPrivateKey(encryptedSize, importedPriv);

                    formData.append(`file_${0}`, encryptedBlob, secureName);
                    formData.append(`size_${0}`, encryptedSize);
                    formData.append(`signed_name_${0}`, signedName);
                    formData.append(`signed_blob_${0}`, signedBlob);
                    formData.append(`signed_size_${0}`, signedSize);
                    formData.append(`file_id_${0}`, fileId);
                    formData.append('file_count', 1);
                    signed_data = await signLogAction("MANAGE")
                    formData.append('client_sign', signed_data.signature)
                    formData.append('timestamp', signed_data.timestamp)

                    UiManager.showToast('info', 'Uploading Encrypted Data...');
                    
                    $.ajax({
                        url: 'upload_files_doctor',
                        type: 'POST',
                        data: formData,
                        processData: false,
                        contentType: false,
                        success: (data) => {
                            if (data.status === 'success'){ 
                                UiManager.showToast('success', 'Request for file deletion has been sent.');
                                this.loadFiles(this.currentFolderId);
                            } else {
                                UiManager.showToast('error', data.error);
                            }
                        },
                        error: (err) => {
                            UiManager.showToast('error', 'Upload Failed: ' + err);
                            console.error(err);
                        }
                    });

                } catch (e) {
                    console.error(e);
                    UiManager.showToast('error', 'Crypto Error: ' + e.message);
                }
                    }
                });
    },

    uploadEncrypted: async function() {
        const files = document.getElementById('file_input').files;
        if (files.length === 0) {
            UiManager.showToast('warning', 'Please select files first');
            return;
        }

        const folderId = this.currentFolderId;
        if (!folderId) { UiManager.showToast('error', 'Folder not found'); return; }

        try {
            UiManager.showToast('info', 'Starting Encryption...');

            const userKeys = await KeyManager.getKey();
            const importedPriv = await importPrivateKey(userKeys._privateKey, 'decrypt');
            const importedPub = await importPublicKey(userKeys._publicKey, 'verify');

            let signed_data = await signLogAction("PROVIDE");
            const meta = await $.post('get_folder_metadata', {
                'folder_id': folderId, 
                'csrfmiddlewaretoken': this.csrfToken,
                'action': "PROVIDE",
                'client_sign': signed_data.signature, 
                'timestamp': signed_data.timestamp
            });

            if (meta.error) throw new Error(meta.error);
            
            // Verify the keys
            const is_symmetric_key_valid = await verifySignatureWithPublicKey(meta.enc_sym, meta.sig_sym, importedPub);
            const is_hmac_key_valid = await verifySignatureWithPublicKey(meta.enc_hmac, meta.sig_hmac, importedPub);
            if(!is_symmetric_key_valid || !is_hmac_key_valid) {
                const signed_data = await signLogAction("MANAGE");
                $.ajax({
                    url: "delete_folder",
                    type: "post",
                    data: {'user_id': this.userId, 'folder_id': folderId, 'action': "MANAGE", 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp},
                    headers: {'X-CSRFToken': this.csrfToken},
                    success: (data) => {
                        if(data.Status) {
                            Swal.fire('Deleted!', 'Folder has been deleted. The keys folder has been corrupted!', 'error');
                        }
                    }
                });
                return;
            }
            // Decrypt symmetric key
            const symmetric_key_base64 = await decryptWithPrivateKey(meta.enc_sym, importedPriv);
            const folderKey = await importKey(base64ToArrayBuffer(symmetric_key_base64));
            // Decrypt HMAC key
            const hmac_key_base64 = await decryptWithPrivateKey(meta.enc_hmac, importedPriv);
            const hmac_key = await importHmacKey(base64ToArrayBuffer(hmac_key_base64));

            const formData = new FormData();
            formData.append('parent_id', folderId);
            formData.append('csrfmiddlewaretoken', this.csrfToken);

            for (let i = 0; i < files.length; i++) {
                const file = files[i];

                const encryptedBytes = await encryptImage(file, folderKey); 
                const encryptedBlob = new Blob([encryptedBytes], {type: 'application/octet-stream'});
                const secureName = await encryptFilename(file.name, folderKey);
                const encryptedSize = JSON.stringify(await encryptData(String(encryptedBlob.size), folderKey));

                const hmacName = await generateMAC(secureName, hmac_key);
                const hmacBlob = await generateMAC(encryptedBlob, hmac_key);
                const hmacSize = await generateMAC(encryptedSize, hmac_key);

                formData.append(`file_${i}`, encryptedBlob, secureName);
                formData.append(`size_${i}`, encryptedSize);
                formData.append(`hmac_name_${i}`, hmacName);
                formData.append(`hmac_blob_${i}`, hmacBlob);
                formData.append(`hmac_size_${i}`, hmacSize);
            }

            formData.append('file_count', files.length);
            formData.append('action', "MANAGE");
            signed_data = await signLogAction("MANAGE");
            formData.append('client_sign', signed_data.signature);
            formData.append('timestamp', signed_data.timestamp);

            UiManager.showToast('info', 'Uploading Encrypted Data...');
            
            $.ajax({
                url: 'upload_files',
                type: 'POST',
                data: formData,
                processData: false,
                contentType: false,
                success: (data) => {
                    if (data.status === 'success') {
                        UiManager.showToast('success', 'Secure Upload Complete');
                        $('#uploadModal').modal('hide');
                        $('#file_input').fileinput('clear');
                        this.loadFiles(folderId);
                    } else {
                        UiManager.showToast('error', data.error);
                    }
                },
                error: (err) => {
                    UiManager.showToast('error', 'Upload Failed: ' + err);
                    console.error(err);
                }
            });

        } catch (e) {
            console.error(e);
            UiManager.showToast('error', 'Crypto Error: ' + e.message);
        }
    },

    uploadEncryptedDoctor: async function() {
        const files = document.getElementById('file_input').files;
        if (files.length === 0) {
            UiManager.showToast('warning', 'Please select files first');
            return;
        }

        const folderId = this.currentFolderId;
        if (!folderId) { UiManager.showToast('error', 'Folder not found'); return; }

        try {
            UiManager.showToast('info', 'Starting Encryption...');

            const userKeys = await KeyManager.getKey();
            let importedPriv = await importPrivateKey(userKeys._privateKey, 'decrypt');
            let importedPub = await importPublicKey(userKeys._publicKey, 'verify');

            const signed_data = await signLogAction("PROVIDE");
            const meta = await $.post('get_folder_metadata', {
                'folder_id': folderId, 
                'csrfmiddlewaretoken': this.csrfToken,
                'action': "PROVIDE",
                'client_sign': signed_data.signature, 
                'timestamp': signed_data.timestamp
            });

            if (meta.error) throw new Error(meta.error);
            if (meta.owner_public_key) importedPub = await importPublicKey(meta.owner_public_key, 'verify');
            
            // Verify the keys
            const is_symmetric_key_valid = await verifySignatureWithPublicKey(meta.enc_sym, meta.sig_sym, importedPub);
            if(!is_symmetric_key_valid) {
                const signed_data = await signLogAction("MANAGE");
                $.ajax({
                    url: "delete_folder",
                    type: "post",
                    data: {'user_id': this.userId, 'folder_id': folderId, 'action': "MANAGE", 'client_sign': signed_data.signature, 'timestamp': signed_data.timestamp},
                    headers: {'X-CSRFToken': this.csrfToken},
                    success: (data) => {
                        if(data.Status) {
                            Swal.fire('Deleted!', 'Folder has been deleted. The keys folder has been corrupted!', 'error');
                        }
                    }
                });
                return;
            }
            // Decrypt symmetric key
            const symmetric_key_base64 = await decryptWithPrivateKey(meta.enc_sym, importedPriv);
            const folderKey = await importKey(base64ToArrayBuffer(symmetric_key_base64));

            const formData = new FormData();
            formData.append('parent_id', folderId);
            formData.append('csrfmiddlewaretoken', this.csrfToken);

            for (let i = 0; i < files.length; i++) {
                const file = files[i];

                const encryptedBytes = await encryptImage(file, folderKey); 
                const encryptedBlob = new Blob([encryptedBytes], {type: 'application/octet-stream'});
                const secureName = await encryptFilename(file.name, folderKey);
                const encryptedSize = JSON.stringify(await encryptData(String(encryptedBlob.size), folderKey));

                importedPriv = await importPrivateKey(userKeys._privateKey, 'sign');
                const signedName = await signWithPrivateKey(secureName, importedPriv);
                const signedBlob = await signWithPrivateKey(encryptedBlob, importedPriv);
                const signedSize = await signWithPrivateKey(encryptedSize, importedPriv);

                formData.append(`file_${i}`, encryptedBlob, secureName);
                formData.append(`size_${i}`, encryptedSize);
                formData.append(`signed_name_${i}`, signedName);
                formData.append(`signed_blob_${i}`, signedBlob);
                formData.append(`signed_size_${i}`, signedSize);
            }

            formData.append('file_count', files.length);
            signed_data = await signLogAction("MANAGE")
            formData.append('client_sign', signed_data.signature)
            formData.append('timestamp', signed_data.timestamp)

            UiManager.showToast('info', 'Uploading Encrypted Data...');
            
            $.ajax({
                url: 'upload_files_doctor',
                type: 'POST',
                data: formData,
                processData: false,
                contentType: false,
                success: (data) => {
                    if (data.status === 'success') {
                        UiManager.showToast('success', 'Secure Upload Complete');
                        $('#uploadModal').modal('hide');
                        $('#file_input').fileinput('clear');
                        this.loadFiles(folderId);
                    } else {
                        UiManager.showToast('error', data.error);
                    }
                },
                error: (err) => {
                    UiManager.showToast('error', 'Upload Failed: ' + err);
                    console.error(err);
                }
            });

        } catch (e) {
            console.error(e);
            UiManager.showToast('error', 'Crypto Error: ' + e.message);
        }
    },
};