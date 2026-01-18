const AuthManager = {
    csrfToken: null,

    init: function(token) {
        this.csrfToken = token;

        $('#login-form').on('submit', (e) => this.handleLogin(e));
        $('#step-patient-form').on('submit', (e) => this.encryptAndSubmitPatientData(e));
        $('#step-doctor-form').on('submit', (e) => this.encryptAndSubmitDoctorData(e));

        // Bind Role Buttons
        $('.btn-role-select').on('click', function() {
            AuthManager.showSignupForm($(this).data('role'));
        });
        $('.btn-back').on('click', function() {
            AuthManager.resetSignup();
        });

        if ($(".alert-danger").length > 0) {
            $('#pills-login').removeClass('show active');
            $('#pills-login-tab').removeClass('active');
            $('#pills-signup').addClass('show active');
            $('#pills-signup-tab').addClass('active');
            this.resetSignup(); 
        }
    },

    showSignupForm: function(role) {
        $("#step-role-select").hide();
        $("#signup-header").text("Complete your " + role + " registration.");
        if (role === 'patient') {
            $("#step-patient-form").show();
            $("#step-doctor-form").hide();
        } else if (role === 'doctor') {
            $("#step-doctor-form").show();
            $("#step-patient-form").hide();
        }
    },

    resetSignup: function() {
        $(".signup-form").hide();
        $("#signup-header").text("Select your role to continue registration");
        $("#step-role-select").show();
    },

    encryptAndSubmitPatientData: async function(event) {
        event.preventDefault();
        const email = document.getElementById('p-email').value;
        const firstname = document.getElementById('p-firstname').value;
        const lastname = document.getElementById('p-lastname').value;
        const birthdate = document.getElementById('p-birthdate').value;
        const password = document.getElementById('p-password').value;

        const encrypted_data = await handleRegistration({ email, firstname, lastname, birthdate, password });

        if (!encrypted_data || encrypted_data.length < 20) {
            Swal.fire('Error', 'Encryption failed (empty encrypted payload)', 'error');
            return;
        }

        const payloadInput = document.querySelector('#hidden-redirect-form input[name="encrypted_payload"]');
        if (!payloadInput) {
            Swal.fire('Error', 'Hidden input (name="encrypted_payload") not found in #hidden-redirect-form', 'error');
            return;
        }

        payloadInput.value = encrypted_data;
        document.getElementById('hidden-redirect-form').submit();
    },

    encryptAndSubmitDoctorData: async function(event) {
        event.preventDefault();

        const email = document.getElementById('d-email').value;
        const firstname = document.getElementById('d-firstname').value;
        const lastname = document.getElementById('d-lastname').value;
        const organization = document.getElementById('d-organization').value;
        const password = document.getElementById('d-password').value;

        const certInput = document.querySelector('#step-doctor-form input[name="certificate"]');
        if (!certInput || !certInput.files || certInput.files.length === 0) {
            Swal.fire('Missing certificate', 'Doctor certificate is required', 'error');
            return;
        }

        const certFile = certInput.files[0];
        if (!certFile) {
            Swal.fire('Missing certificate', 'Doctor certificate is required', 'error');
            return;
        }

        const encrypted_data = await handleRegistration({
            email,
            firstname,
            lastname,
            organization,
            password
        });

        if (!encrypted_data || encrypted_data.length < 20) {
            Swal.fire('Error', 'Encryption failed (empty encrypted payload)', 'error');
            return;
        }

        // Put payload into hidden input inside the real doctor multipart form
        const payloadField = document.getElementById('doctor_encrypted_payload');
        if (!payloadField) {
            Swal.fire('Error', 'Missing #doctor_encrypted_payload input in step-doctor-form', 'error');
            return;
        }
        payloadField.value = encrypted_data;

        // Submit the real multipart form (includes the certificate upload)
        const form = document.getElementById('step-doctor-form');
        if (!form) {
            Swal.fire('Error', 'Doctor form not found (#step-doctor-form)', 'error');
            return;
        }

        // Avoid shadowing when there is <input name="submit"> inside the form
        HTMLFormElement.prototype.submit.call(form);
    },

    handleLogin: async function(event) {
        if(event) event.preventDefault();
        const email = document.getElementById('login_email').value;
        const password = document.getElementById('login_password').value;
        
        if (!(isEmailCorrect(email) && isPasswordStrong(password))){
            return;
        }

        try {
            const challengeResponse = await $.ajax({
                url: 'generate_challenge',
                type: 'post',
                data: { 'email': email },
                headers: {'X-CSRFToken': this.csrfToken},
            });

            if (!challengeResponse.challenge) {
                Swal.fire('Error', 'User not found or server error.', 'error');
                return;
            }

            let user_data;
            try {
                user_data = await handleProfile(challengeResponse.user_data, password);
                if (!user_data) throw new Error("Decryption returned null");
            } catch (cryptoError) {
                console.error("Crypto fail:", cryptoError);
                Swal.fire('Authentication Failed', 'Wrong email/password.', 'error');
                return;
            }

            const keyPair = KeyManager.getKey();
            const encPrivateKey = await importPrivateKey(keyPair._privateKey, 'decrypt');
            const decryptedBuffer = await decryptWithPrivateKey(challengeResponse.challenge, encPrivateKey);
            
            const signPrivateKey = await importPrivateKey(keyPair._privateKey, 'sign');
            const signature = await signWithPrivateKey(decryptedBuffer, signPrivateKey);

            const loginResponse = await $.ajax({
                url: 'get_entry',
                type: 'post',
                data: { 
                    'email': email, 
                    'signed_challenge': signature,
                    'action_btn': 'Login'
                },
                headers: {'X-CSRFToken': this.csrfToken}
            });

            if (loginResponse.error) {
                console.log("Failed to login: " + loginResponse.error);
            } else {
                htmx.ajax('GET', '/dashboard', {target: 'body', pushUrl: true});
            }

        } catch (error) {
            console.error(error);
        }
    },

    logout: function() {
        if(typeof KeyManager !== 'undefined') {
            KeyManager.clear();
        }

        sessionStorage.clear();
        localStorage.clear();

        window.location.href = "/logout";
    },
};