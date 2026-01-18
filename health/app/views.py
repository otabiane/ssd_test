import random, os, json, shutil, base64, secrets, hashlib
from datetime import date
from urllib.parse import unquote
from django.utils import timezone
from django.contrib import messages
from django.http import HttpResponse, FileResponse, JsonResponse
from django.shortcuts import render, redirect
from django.core.files.storage import default_storage
from django.core.mail import send_mail
from django.conf import settings
from django.forms.models import model_to_dict
from cryptography.hazmat.primitives import hashes, serialization 
from cryptography.hazmat.primitives.asymmetric import padding

from app.models import Notification, User, Verification, File, Folder, Shared, Patient, Doctor, Challenge, File_version
from logs.views import create_logs, is_traffic_safe
from app.utils import hmac_data, is_hmac_correct, get_logged_in_user, get_user_by_email, get_user_by_id, sanitize_str, validate_sanitize_email, get_safe_filename, send_email_func

# PKI helpers (Doctor certificate validation)
from app.pki.check_ca import verify_doctor_certificate
from app.pki.exceptions import PKIError


# Auth helpers
def verify_transaction(request, user, action):
    source = request.GET if request.method == 'GET' else request.POST
    timestamp = source.get('timestamp')
    signature = source.get('client_sign')

    if not timestamp or not is_request_fresh(timestamp):
        return False
    
    expected_msg = f"{action}|{timestamp}"

    return verify_user_signature(user.public_key, signature, expected_msg, request)

def is_request_fresh(request_timestamp):
    try:
        client_ts = float(request_timestamp) / 1000.0
        server_ts = timezone.now().timestamp()

        return abs(server_ts - client_ts) < 60 # 60sec max
    except:
        return False
    
def verify_user_signature(public_key_b64, signature_b64, original_message_b64, request):
    pk_der = base64.b64decode(public_key_b64.strip())
    signature = base64.b64decode(signature_b64)
    message_bytes = original_message_b64.encode('utf-8')
    user, role = get_logged_in_user(request)
    
    try:
        public_key = serialization.load_der_public_key(pk_der)
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32,  # Must match the frontend
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        create_logs(request, "SYSTEM", "ERROR", "VERIFY_USER_SIGN", json.dumps({"event": "VERIFY_SIGN_USER", "privileges": role, "message": f"Error while verifying user signature: {e}"}), None)
        return False

def send_email_func(mail, subject, temp_message):
    try:
        send_mail(
            subject,
            temp_message,
            settings.DEFAULT_FROM_EMAIL,
            [mail],
            fail_silently=False
        )
    except Exception as e:
        create_logs(None, "SYSTEM", "ERROR", "SEND_EMAIL", json.dumps({"event": "SEND_EMAIL", "privileges": "SYSTEM", "message": f"Error while sending email to {mail}: {e}"}), None)
        
# views: navigation

def home(request):
    if request.session.get('user_id'):
        return redirect('dashboard')
    return render(request, 'index.html')

def dashboard(request):
    user, role = get_logged_in_user(request)
    if not user:
        return redirect('logout')
    
    if request.GET.get('folder_id'):
        if role == 'patient':
            return render(request, 'dashboard_file.html', {'folder_id': request.GET['folder_id']})
        elif role == 'doctor':
            return render(request, 'shared.html', {'folder_id': request.GET['folder_id']})
    
    if role == 'patient':
        return render(request, 'dashboard.html')
    elif role == 'doctor':
        return render(request, 'shared.html')
    else:
        return redirect('index')

# views: authentication

def generate_challenge(request):
    email = validate_sanitize_email(request.POST.get('email'))
    if not email:
        return JsonResponse({'error': "Invalid email format."})
    
    user, role = get_user_by_email(email)

    if not user:
        return JsonResponse({'error': "User not exists"})
    
    if not is_traffic_safe(request, email):
        return JsonResponse({'error': "Traffic limit exceeded"})
    
    Challenge.objects.filter(user=user).delete()

    raw_nonce = secrets.token_urlsafe(32)  
    challenge = Challenge.objects.create(user=user, challenge=raw_nonce)

    try:
        der_data = base64.b64decode(user.public_key.strip())
        public_key = serialization.load_der_public_key(der_data)

        # Encrypt the STRING, not the database object
        encrypted_blob = public_key.encrypt(
            raw_nonce.encode('utf-8'), # Use the raw string variable here
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        chal_b64 = base64.b64encode(encrypted_blob).decode('utf-8')
    except:
        chal_b64 = raw_nonce

    user_data = model_to_dict(user, exclude=["id", "hmac_created_at", "created_at", "record_size", "hmac_record_size"])

    return JsonResponse({
        "challenge": chal_b64,
        "user_data": user_data
    })

def get_entry(request):
    if request.POST.get('action_btn') == 'Login':
        return signin(request)
    return signup(request)

def signin(request):
    email = validate_sanitize_email(request.POST.get('email'))
    if not email:
        return JsonResponse({'error': "Invalid email format."})
    
    user, role = get_user_by_email(email)

    if not user:
        messages.error(request, "User not exists")
        return redirect('index')

    if Verification.objects.filter(user=user).exists():
        return redirect('verify')
    
    try:
        challenge = Challenge.objects.get(user=user)
        if challenge.expires_at < timezone.now():
            messages.error(request, "Challenge expired")
            return redirect("index")
        
        sig = request.POST.get('signed_challenge')
        if verify_user_signature(user.public_key, sig, challenge.challenge, request) and is_challenge_valid(challenge):
            request.session['user_id'] = user.id
            request.session['user_email'] = user.email
            challenge.delete()
            create_logs(request, user.email, "INFO", "AUTH", json.dumps({"event": "LOGIN", "privileges": role, "message": "User logged in successfully"}), sig)
            return redirect('dashboard')
        else:
            return redirect('verify')
    except Challenge.DoesNotExist:
        pass

    messages.error(request, "Authentication failed")
    return redirect('index')

def signup(request):
    if request.method != "POST":
        return redirect('index')
    
    payload = request.POST.get('encrypted_payload')
    if not payload:
        messages.error(request, 'No data received')
        return redirect('index')

    try:
        data = json.loads(payload)
        email = validate_sanitize_email(data["email"])

        if not email:
            return JsonResponse({'error': "Invalid email format."})
    
        if User.objects.filter(email=email).exists():
            messages.error(request, "User already exists!")
            return redirect('index')

        role = request.POST.get("role")
        field_map = {
            'email': email,
            'hmac_email': data.get("hmac_email"),
            'firstname': data["firstname"],
            'hmac_firstname': data.get("hmac_firstname"),
            'lastname': data["lastname"],
            'hmac_lastname': data.get("hmac_lastname"),
            'public_key': data["public_key"],
            'private_key': data["private_key"],
            'hmac_private_key': data["hmac_private_key"],
            'encrypted_symmetric_key': data["encrypted_symmetric_key"],
            'signed_symmetric_key': data["signed_symmetric_key"],
            'encrypted_hmac_key': data["encrypted_hmac_key"],
            'signed_hmac_key': data["signed_hmac_key"]   
        }

        new_user = None
        if role == "patient":
            new_user = Patient.objects.create(**field_map, birthdate = data["birthdate"], hmac_birthdate = data["hmac_birthdate"])
        else:
            # -----------------------------------------------------------------
            # PKI: Doctor certificate is mandatory at signup.
            # The frontend submits a multipart form containing:
            #   - encrypted_payload (JSON)
            #   - certificate file (PEM/CRT)
            # -----------------------------------------------------------------
            cert_file = request.FILES.get("certificate")
            if not cert_file:
                messages.error(request, "Doctor certificate required")
                return redirect('index')

            try:
                cert_pem = cert_file.read().decode("utf-8")
            except Exception:
                messages.error(request, "Could not read certificate file")
                return redirect('index')

            try:
                # Validate chain (Doctor -> Org CA -> Root CA) + validity period
                verify_doctor_certificate(cert_pem)
            except PKIError as e:
                messages.error(request, f"Invalid certificate: {str(e)}")
                return redirect('index')

            new_user = Doctor.objects.create(
                **field_map,
                # keep organization encrypted as expected by frontend
                organization=data["organization"],
                hmac_organization=data["hmac_organization"],
                certificate=cert_pem,
                hmac_certificate=hmac_data(cert_pem),
            )

        # Send OTP for verification (using the automatically created User ID)
        otp = str(random.randint(100000, 999999))
        Verification.objects.create(user=new_user, otp=otp, hmac_otp=hmac_data(otp))
        send_email_func(email, "OTP", "Your verification code is: " + otp)

        messages.success(request, "Account created! Please verify your email.")
        create_logs(request, email, "INFO", "AUTH", json.dumps({"event": "SIGNUP", "privileges": role, "message": "User signup successfully"}), None)
        return redirect('verify')
    except Exception as e:
        create_logs(request, "SYSTEM", "ERROR", "SIGNUP", f"Error signing up: {e}", None)
        

def verify(request):
    list(messages.get_messages(request))
    return render(request, 'verify.html')

def validate_otp(request):
    email = validate_sanitize_email(request.POST.get('email_field'))
    if not email:
        return JsonResponse({'error': "Invalid email format."})
    
    otp_input = request.POST.get('otp_field')
    user, role = get_user_by_email(email)

    if not user:
        messages.error(request, "User not found")
        return redirect('index')
    
    try:
        verif = Verification.objects.get(user=user)

        # Check if OTP is expired
        if verif.expires_at < timezone.now():
            verif.delete()
            # renew
            new_otp = str(random.randint(100000, 999999))
            Verification.objects.create(user=user, otp=new_otp, hmac_otp=hmac_data(new_otp))
            send_email_func(user.email, "OTP", "Your OTP has expired. Your verification code is: " + new_otp)
            messages.error(request, "Your OTP has expired. A new OTP was sent.")
            return render(request, 'verify.html')

        if verif.otp == otp_input.strip():
            verif.delete()
            messages.success(request, "Verification successful!")
            return redirect('index')
        else:
            messages.error(request, "Invalid OTP. Please try again.")
            return render(request, 'verify.html')

    except Verification.DoesNotExist:
        messages.error(request, "No verifications pending")
        return redirect('index')

def signout(request):
    request.session.flush()
    return redirect('index')

def is_challenge_valid(challenge):
    if is_hmac_correct(challenge.hmac_challenge, challenge.challenge) and \
        is_hmac_correct(challenge.hmac_created_at, challenge.created_at.isoformat()) and \
        is_hmac_correct(challenge.hmac_record_size, challenge.record_size) and \
        is_hmac_correct(challenge.hmac_expires_at, challenge.expires_at.isoformat()):
        return True
    return False

def is_notification_valid(notif):
    if is_hmac_correct(notif.hmac_message, notif.message) and \
        is_hmac_correct(notif.hmac_created_at, notif.created_at.isoformat()) and \
        is_hmac_correct(notif.hmac_record_size, notif.record_size):
        return True
    return False

def get_public_key(request):
    target_email = validate_sanitize_email(request.POST.get('email'))

    if not target_email:
        return JsonResponse({'error': "Invalid email format."})
    
    user, role = get_logged_in_user(request)
    if not (request.session.get('user_id') or target_email):
        return JsonResponse({'error': "Auth required"}, status=403)
    
    if not verify_transaction(request, user, "AUTH"):
        create_logs(request, user.email, "WARNING", "REPLAY_ATTACK", "Invalid signature or timestamp.", None)
        return JsonResponse({'status': False, 'error': "Request timeout."})

    try:
        target_user = User.objects.get(email=target_email)
        create_logs(request, target_email, "INFO", request.POST.get('action'), json.dumps({"event": "GET_PUBLIC_KEY", "privileges": role, "message": f"got keys of {target_email}."}), request.POST.get('client_sign'))
        return JsonResponse({'public_key': target_user.public_key})

    except (User.DoesNotExist) as e:
        create_logs(request, "SYSTEM", "ERROR", "AUTH", json.dumps({"event": "GET_PUBLIC_KEY", "privileges": role, "message": f"Error while getting public key of: {target_email}. Error: {e}"}), None)
        return JsonResponse({'error': "User not found"}, status=404)

# views: folder & files

def save_folder(request):
    user, role = get_logged_in_user(request)
    if not user or role != 'patient':
        return JsonResponse({'status': False, 'error': "Permission Denied"})
    
    if not is_traffic_safe(request, user.email): 
        return JsonResponse({'status': False, 'error': "Traffic limit exceeded. Action blocked."})
    
    if not verify_transaction(request, user, "MANAGE"):
        create_logs(request, user.email, "WARNING", "REPLAY_ATTACK", "Invalid signature or timestamp.", None)
        return JsonResponse({'status': False, 'error': "Request timeout."})
    
    name = request.POST.get('name')
    hmac_name = request.POST.get('hmac_name')
    date = request.POST.get('date')
    hmac_date = request.POST.get('hmac_date')
    enc_sym = request.POST.get('encrypted_symmetric_key')
    sig_sym = request.POST.get('signed_symmetric_key')
    enc_hmac = request.POST.get('encrypted_hmac_key')
    sig_hmac = request.POST.get('signed_hmac_key')

    if not all([name, hmac_name, date, hmac_date, enc_sym, sig_sym, enc_hmac, sig_hmac]):
        return JsonResponse({'status': False, 'error': "Missing cryptographic data"})

    safe_folder_name = get_safe_filename(json.loads(name).get('encrypted_data'))

    link = f"user_data/{user.id}/{safe_folder_name}"

    try:
        os.makedirs(link, exist_ok=True)
        Folder.objects.create(
            user=user,
            name=name, 
            hmac_name=hmac_name,
            appointment_date=date,
            hmac_appointment_date=hmac_date,
            path=str(link),  
            encrypted_symmetric_key=enc_sym,
            signed_symmetric_key=sig_sym,
            encrypted_hmac_key=enc_hmac,
            signed_hmac_key=sig_hmac
        )

        create_logs(request, user.email, "INFO", request.POST.get('action'), json.dumps({"event": "SAVE_FOLDER", "privileges": role, "message": f"folder saved."}), request.POST.get('client_sign'))    
        return JsonResponse({'status': True})
    except Exception as e:
        create_logs(request, "SYSTEM", "ERROR", "SAVE_FOLDER", json.dumps({"event": "SAVE_FOLDER", "privileges": role, "message": f"Error while saving folder: {e}"}), None)
        return JsonResponse({'status': False, 'error': str(e)})
        

def upload_files(request):
    user, role = get_logged_in_user(request)
    if not user or role != 'patient':
        return JsonResponse({'status': False, 'error': "Permission Denied"})

    if not is_traffic_safe(request, user.email): 
        return JsonResponse({'status': False, 'error': "Traffic limit exceeded. Action blocked."})
    
    if not verify_transaction(request, user, "MANAGE"):
        create_logs(request, user.email, "WARNING", "REPLAY_ATTACK", "Invalid signature or timestamp.", None)
        return JsonResponse({'status': False, 'error': "Request timeout."})
    
    try:
        folder_id = int(request.POST['parent_id'])
        if not folder_id: raise Exception("Missing folder ID")

        folder = Folder.objects.get(id=folder_id)
        if folder.user.id != user.id: raise Exception("Not your folder")
        
        file_count = int(request.POST.get('file_count', 0))
        count = 0

        for i in range(file_count):
            # Extract indexed data from POST and FILES
            encrypted_file = request.FILES.get(f'file_{i}')
            encrypted_size = request.POST.get(f'size_{i}')
            hmac_name = request.POST.get(f'hmac_name_{i}')
            hmac_blob = request.POST.get(f'hmac_blob_{i}')
            hmac_size = request.POST.get(f'hmac_size_{i}')

            if not encrypted_file:
                continue

            safe_filename = get_safe_filename(encrypted_file.name)
            safe_folder_name = get_safe_filename(json.loads(folder.name).get('encrypted_data'))

            relative_path = os.path.join(str(user.id), safe_folder_name, safe_filename)
            file_name = default_storage.save(relative_path, encrypted_file)
            file_url = default_storage.url(file_name)

            File.objects.create(
                user=user,
                folder=folder,
                title=safe_filename,
                hmac_title=hmac_name,
                hmac_file=hmac_blob,
                size=encrypted_size,
                hmac_size=hmac_size,
                upload_date=date.today(),
                link=file_url
            )
            count += 1
        
        create_logs(request, user.email, "INFO", request.POST.get('action'), json.dumps({"event": "UPLOAD_FILE", "privileges": role, "message": f"{count} file(s) uploaded."}), request.POST.get('client_sign'))    
        return JsonResponse({'status': 'success', 'count': count})
    
    except Exception as e:
        create_logs(request, "SYSTEM", "ERROR", "UPLOAD_FILE", json.dumps({"event": "UPLOAD_FILE", "privileges": role, "message": f"Error while uploading file(s): {e}"}), None)
        return JsonResponse({'status': False, 'error': str(e)})

def delete_file(request):
    user, role = get_logged_in_user(request)
    if not user:
        return redirect('index')
    
    if not is_traffic_safe(request, user.email): 
        return JsonResponse({'status': False, 'error': "Traffic limit exceeded. Action blocked."})
    
    if not verify_transaction(request, user, "MANAGE"):
        create_logs(request, user.email, "WARNING", "REPLAY_ATTACK", "Invalid signature or timestamp.", None)
        return JsonResponse({'status': False, 'error': "Request timeout."})
    
    try:
        fid = int(request.POST.get('file_id'))
        f = File.objects.get(id=fid)
        fv = File_version.objects.filter(file_id=fid)

        if f.user.id != user.id:
            return JsonResponse({'Status': False, 'error': "Permission Denied"})
        
        try:
            link_path = unquote(f.link)
            media_url = settings.MEDIA_URL

            if link_path.startswith(media_url):
                relative_name = link_path.replace(media_url, "", 1)
            elif link_path.startswith('/'):
                relative_name = f.link[1:]
            else:
                relative_name = link_path
                
            full_path = os.path.join(settings.MEDIA_ROOT, relative_name)
            
            if os.path.exists(full_path):
                os.remove(full_path)
            
        except: 
            create_logs(request, "SYSTEM", "ERROR", "DELETE_FILE", json.dumps({"event": "DELETE_FILE", "privileges": role, "message": f"Error while deleting file of {user.email}: {e}"}), None)
            
        f.delete()
        fv.delete()
        
        create_logs(request, user.email, "INFO", request.POST.get('action'), json.dumps({"event": "DELETE_FILE", "privileges": role, "message": f"file(s) deleted."}), request.POST.get('client_sign'))    
        return JsonResponse({'Status': True})
    except Exception as e:
        create_logs(request, "SYSTEM", "ERROR", "DELETE_FILE", json.dumps({"event": "DELETE_FILE", "privileges": role, "message": f"Error while deleting file: {e}"}), None)
        return JsonResponse({'Status': False, 'error': str(e)})

def delete_file_version(request):
    user, role = get_logged_in_user(request)
    if not is_traffic_safe(request, user.email):
        return JsonResponse({'Status': False, 'error': "Traffic limit exceeded."})
    
    if not verify_transaction(request, user, "MANAGE"):
        create_logs(request, user.email, "WARNING", "REPLAY_ATTACK", "Invalid signature or timestamp.", None)
        return JsonResponse({'status': False, 'error': "Request timeout."})

    if not user and role != "patient":
        return redirect('index')

    try:
        fv = File_version.objects.filter(id=request.POST.get('file_id'))
        fv.delete()
        create_logs(request, user.email, "INFO", request.POST.get('action'), json.dumps({"event": "DELETE_FILE_VERSION", "privileges": role, "message": f"file version(s) deleted."}), request.POST.get('client_sign'))    
        return JsonResponse({'Status': True})
    except Exception as e:
        create_logs(request, "SYSTEM", "ERROR", "DELETE_FILE_VERSION", json.dumps({"event": "DELETE_FILE_VERSION", "privileges": role, "message": f"Error while deleting file version: {e}"}), None)
        return JsonResponse({'Status': False, 'error': str(e)})

def get_file_version(request):
    user, role = get_logged_in_user(request)
    
    if not verify_transaction(request, user, "MANAGE"):
        create_logs(request, user.email, "WARNING", "REPLAY_ATTACK", "Invalid signature or timestamp.", None)
        return JsonResponse({'status': False, 'error': "Request timeout."})
    
    try:
        f = model_to_dict(File_version.objects.get(id=request.POST.get('file_id')))
        create_logs(request, user.email, "INFO", request.POST.get('action'), json.dumps({"event": "GET_FILE_VERSION", "privileges": role, "message": f"got file version."}), request.POST.get('client_sign'))    
        return JsonResponse({'Status': True, "data": f})
    except File_version.DoesNotExist as e:
        create_logs(request, "SYSTEM", "ERROR", "GET_FILE_VERSION", json.dumps({"event": "GET_FILE_VERSION", "privileges": role, "message": f"Error while getting file version: {e}"}), None)
        return JsonResponse({'Status': True, "data": []})


def delete_file_doctor(request):
    user, role = get_logged_in_user(request)
    if not user :
        return JsonResponse({'status': False, 'error': "Permission Denied"})
        
    if not verify_transaction(request, user, "MANAGE"):
        create_logs(request, user.email, "WARNING", "REPLAY_ATTACK", "Invalid signature or timestamp.", None)
        return JsonResponse({'status': False, 'error': "Request timeout."})

    try:
        fid = int(request.POST.get('file_id'))
        folder_id = int(request.POST.get('folder_id'))  
        try: 
            f = File_version.objects.get(id=fid, uploaded_by_id=user.id)
        except File_version.DoesNotExist:
            f = File_version.objects.get(folder_id=folder_id, id=fid)
        
        if not (f.uploaded_by_id == user.id or f.folder.user.id == user.id):
            return JsonResponse({'Status': False, 'error': "Permission Denied"})
        
        try:
            link_path = unquote(f.blob_url)
            media_url = settings.MEDIA_URL

            if link_path.startswith(media_url):
                relative_name = link_path.replace(media_url, "", 1)
            elif link_path.startswith('/'):
                relative_name = f.blob_url[1:]
            else:
                relative_name = link_path
                
            full_path = os.path.join(settings.MEDIA_ROOT, relative_name)
            
            if os.path.exists(full_path): 
                os.remove(full_path)
        except: 
            pass

        f.delete()
        create_logs(request, user.email, "INFO", request.POST.get('action'), json.dumps({"event": "DELETE_FILE_DOCTOR", "privileges": role, "message": f"Doctor deleted file(s)."}), request.POST.get('client_sign'))    
        return JsonResponse({'Status': True})
    except Exception as e:
        create_logs(request, "SYSTEM", "ERROR", "DELETE_FILE_DOCTOR", json.dumps({"event": "DELETE_FILE_DOCTOR", "privileges": role, "message": f"Error while deleting file as doctor: {e}"}), None)
        return JsonResponse({'Status': False, 'error': str(e)})


def delete_folder(request):
    user, role = get_logged_in_user(request)
    if not user:
        return redirect('index')
    
    if not verify_transaction(request, user, "MANAGE"):
        create_logs(request, user.email, "WARNING", "REPLAY_ATTACK", "Invalid signature or timestamp.", None)
        return JsonResponse({'status': False, 'error': "Request timeout."})
    
    try:
        fid = int(request.POST.get('folder_id'))
        f = Folder.objects.get(id=fid)
        if f.user.id == user.id:
            if os.path.exists(f.path):
                shutil.rmtree(f.path)
            f.delete()
            create_logs(request, user.email, "INFO", request.POST.get('action'), json.dumps({"event": "DELETE_FOLDER", "privileges": role, "message": f"Folder deleted."}), request.POST.get('client_sign'))    
            return JsonResponse({'Status': True})
    except Exception as e: 
        create_logs(request, "SYSTEM", "ERROR", "DELETE_FOLDER", json.dumps({"event": "DELETE_FOLDER", "privileges": role, "message": f"Error while deleting folder: {e}"}), None)
    return JsonResponse({'Status': False})

def file_download(request):
    user_id = request.session.get('user_id')
    file_url = request.GET.get('era', '').strip()
    user, role = get_logged_in_user(request)

    if not user:
        return HttpResponse("Unauthorized", status=401)

    if not is_traffic_safe(request, user.email): 
        return JsonResponse({'status': False, 'error': "Traffic limit exceeded. Action blocked."})
    
    if not verify_transaction(request, user, "DOWNLOAD"):
        create_logs(request, user.email, "WARNING", "REPLAY_ATTACK", "Invalid signature or timestamp.", None)
        return JsonResponse({'status': False, 'error': "Request timeout."})

    if not user_id or not file_url:
        return HttpResponse("Missing parameters", status=400)
    
    try:
        file_path = unquote(file_url)
        if ".." in file_path or file_path.startswith("/"):
            pass

        media_url = settings.MEDIA_URL

        if file_path.startswith(media_url):
            relative_name = file_path.replace(media_url, "", 1)
        elif file_path.startswith('/'):
            relative_name = file_path[1:]
        else:
            relative_name = file_path

        clean_relative = os.path.normpath(relative_name)
        if ".." in clean_relative:
            create_logs(request, "SYSTEM", "WARNING", "DOWNLOAD_FILE", "Path traversal attempt detected", None)
            return HttpResponse("Security Violation", status=403)

        full_path = os.path.join(settings.MEDIA_ROOT, clean_relative)
        
        create_logs(request, user.email, "INFO", "DOWNLOAD", json.dumps({"event": "DOWNLOAD_FILE", "privileges": role, "message": f"Downloaded file"}), None)
        return FileResponse(open(full_path, 'rb'))
    except FileNotFoundError as e:
        create_logs(request, "SYSTEM", "ERROR", "DOWNLOAD_FILE", json.dumps({"event": "DOWNLOAD_FILE", "privileges": 'user', "message": f"Error while downloading file: {e}"}), None)
        return HttpResponse("File not found on server", status=404)
    except Exception as e:
        create_logs(request, "SYSTEM", "ERROR", "DOWNLOAD_FILE", json.dumps({"event": "DOWNLOAD_FILE", "privileges": 'user', "message": f"Error while downloading file: {e}"}), None)
        return HttpResponse(f"Server Error: {str(e)}", status=500)

def folder_provider(request):
    user, role = get_logged_in_user(request)
    if not user:
        return JsonResponse([], safe=False)
    
    if not verify_transaction(request, user, "PROVIDE"):
        create_logs(request, user.email, "WARNING", "REPLAY_ATTACK", "Invalid signature or timestamp.", None)
        return JsonResponse([], safe=False)

    folders = Folder.objects.filter(user_id=user.id).values() 
    data = []
    for f in folders:
        shares = Shared.objects.filter(folder_id=f['id'])
        f['doctors'] = [{'id': s.id, 'email': s.doctor.email} for s in shares]
        data.append(f)

    create_logs(request, user.email, "INFO", request.POST.get('action'), json.dumps({"event": "FOLDER_PROVIDER", "privileges": role, "message": f"Folder provided."}), request.POST.get('client_sign'))        
    return JsonResponse(data, safe=False)

def file_provider(request):
    user, role = get_logged_in_user(request)
    fid = request.POST.get('folder_id')
    
    if not verify_transaction(request, user, "PROVIDE"):
        create_logs(request, user.email, "WARNING", "REPLAY_ATTACK", "Invalid signature or timestamp.", None)
        return JsonResponse([], safe=False)
    
    if user and fid:
        files = File.objects.filter(user_id=user.id, folder_id=fid).values()
        file_versions = File_version.objects.filter(folder_id=fid).values(
            'id', 'title', 'signed_title', 'uploaded_by__email', 'blob_url', 'size', 'signed_size', 'signed_blob', 'file__id'
        )
        create_logs(request, user.email, "INFO", request.POST.get('action'), json.dumps({"event": "FILE_PROVIDER", "privileges": role, "message": f"{len(list(files))} file(s) provided."}), request.POST.get('client_sign'))    
        return JsonResponse(list(files) + list(file_versions), safe=False)
    return JsonResponse([], safe=False)

def get_folder_metadata(request):
    user, role = get_logged_in_user(request)
    if not user: return JsonResponse({'error': "Auth required"})

    if not verify_transaction(request, user, "PROVIDE"):
        create_logs(request, user.email, "WARNING", "REPLAY_ATTACK", "Invalid signature or timestamp.", None)
        return JsonResponse({'status': False, 'error': "Request timeout."})

    fid = request.POST.get('folder_id')
    if not fid: return JsonResponse({'error': "Missing ID"})
    
    try:        
        if role == 'patient':
            folder = Folder.objects.get(id=fid, user=user)
            return JsonResponse({
                'enc_sym': folder.encrypted_symmetric_key,
                'sig_sym': folder.signed_symmetric_key,
                'enc_hmac': folder.encrypted_hmac_key,
                'sig_hmac': folder.signed_hmac_key,
                'owner_public_key': None
            })
        elif role == 'doctor':
            share = Shared.objects.get(folder_id=fid, doctor=user)
            return JsonResponse({
                'enc_sym': share.encrypted_symmetric_key,
                'sig_sym': share.signed_symmetric_key,
                'enc_hmac': share.encrypted_hmac_key,
                'sig_hmac': share.signed_hmac_key,
                'owner_public_key': share.patient.public_key
            })

        create_logs(request, user.email, "INFO", request.POST.get('action'), json.dumps({"event": "GET_FOLDER_METADATA", "privileges": role, "message": f"Folder metadata provided."}), request.POST.get('client_sign'))    
    except Exception as e:
        create_logs(request, "SYSTEM", "ERROR", "GET_FOLDER_METADATA", json.dumps({"event": "GET_FOLDER_METADATA", "privileges": role, "message": f"Error while getting metadata for file id:${fid}. Error: {e}"}), None)
        return JsonResponse({'error': str(e)}, status=404)

# views: sharing

def list_doctors(request):
    try:
        shared_ids = Shared.objects.filter(patient_id=request.session["user_id"]).values_list("doctor_id", flat=True)
        docs = Doctor.objects.exclude(id__in=shared_ids).values_list('email', flat=True)
        return JsonResponse(list(docs), safe=False)        
    except Exception as e:
        create_logs(request, "SYSTEM", "ERROR", "LIST_DOCTOR", json.dumps({"event": "LIST_DOCTOR", "privileges": 'user', "message": f"Error while getting doctor list: {e}"}), None)
        return JsonResponse({'status': False, 'error': "Failed to retrieve doctors."}, status=500)

def check_share(request):
    user, role = get_user_by_id(request.POST.get('user_id'))
    if not user:
        return JsonResponse({'status': False, 'error': "User not identified"})
    
    if not is_traffic_safe(request, user.email): 
        return JsonResponse({'status': False, 'error': "Traffic limit exceeded. Action blocked."})
    
    if not verify_transaction(request, user, "SHARE"):
        create_logs(request, user.email, "WARNING", "REPLAY_ATTACK", "Invalid signature or timestamp.", None)
        return JsonResponse({'status': False, 'error': "Request timeout."})
    
    try:
        doc_email = validate_sanitize_email(request.POST.get('doctor'))

        if not doc_email:
            return JsonResponse({'error': "Invalid email format."})

        folder_id = int(request.POST.get('folder_id'))
        enc_sym = request.POST.get('encrypted_symmetric_key')
        sig_sym = request.POST.get('signed_symmetric_key')
        enc_hmac = request.POST.get('encrypted_hmac_key')
        sig_hmac = request.POST.get('signed_hmac_key')

        if not all([enc_sym, sig_sym, enc_hmac, sig_hmac]):
            return JsonResponse({'status': False, 'error': "Missing cryptographic keys"})

        doctor = Doctor.objects.get(email=doc_email)
        patient = Patient.objects.get(id=int(request.session['user_id']))
        folder = Folder.objects.get(id=folder_id)
        
        if Shared.objects.filter(patient=patient, doctor=doctor, folder=folder).exists():
            return JsonResponse({'status': False, 'error': "Medical report is already shared with this user!"})

        share = Shared.objects.create(
            patient=patient, 
            doctor=doctor, 
            folder=folder, 
            encrypted_symmetric_key=enc_sym,
            signed_symmetric_key=sig_sym,
            encrypted_hmac_key=enc_hmac,
            signed_hmac_key=sig_hmac
        )

        Notification.objects.create(sender=patient, reciever=doctor, shared=share, message=f"Shared a medical record")

        create_logs(request, patient.email, "INFO", request.POST.get('action'), json.dumps({"event": "CHECK_SHARE", "privileges": 'user', "message": f"{patient.email} shared folder(s)."}), request.POST.get('client_sign'))    
        return JsonResponse({'status': True})
    except Exception as e:
        create_logs(request, "SYSTEM", "ERROR", "CHECK_SHARE", json.dumps({"event": "CHECK_SHARE", "privileges": 'user', "message": f"Error while checking sharing: {e}"}), None)
        return JsonResponse({'status': False, 'error': str(e)})

def revoke_share(request):
    user, role = get_logged_in_user(request)
    if not user: return JsonResponse({'error': "Permission Denied"})

    if not is_traffic_safe(request, user.email): 
        return JsonResponse({'status': False, 'error': "Traffic limit exceeded. Action blocked."})

    if not verify_transaction(request, user, "SHARE"):
        create_logs(request, user.email, "WARNING", "REPLAY_ATTACK", "Invalid signature or timestamp.", None)
        return JsonResponse({'status': False, 'error': "Request timeout."})

    try: 
        shared_id = int(request.POST.get('id'))
        share = Shared.objects.get(id=shared_id)

        if share.patient.id != user.id:
            return JsonResponse({'status': False, 'error': "Permission Denied: You are not the owner."})
        
        notif = Notification.objects.filter(shared=share)
        if notif.exists():
            notif.delete()

        share.delete()
    
        create_logs(request, user.email, "INFO", request.POST.get('action'), json.dumps({"event": "REVOKE_SHARE", "privileges": role, "message": f"{user.email} revoked share."}), request.POST.get('client_sign'))    
        return JsonResponse({'status': True})
    except Shared.DoesNotExist as e:
        create_logs(request, "SYSTEM", "ERROR", "REVOKE_SHARE", json.dumps({"event": "REVOKE_SHARE", "privileges": role, "message": f"Error while revoking sharing: {e}"}), None)
        return JsonResponse({'status': False, 'error': "Share not found"})
    except Exception as e:
        create_logs(request, "SYSTEM", "ERROR", "REVOKE_SHARE", json.dumps({"event": "REVOKE_SHARE", "privileges": role, "message": f"Error while revoking sharing: {e}"}), None)
        return JsonResponse({'status': False, 'error': str(e)})

def get_shared(request):
    user, role = get_user_by_id(request.POST.get('user_id'))
    fid = request.POST.get('folder_id')
    if not fid:
        return JsonResponse([], safe=False)
    
    try:
        shares = Shared.objects.filter(folder_id=fid)

        create_logs(request, user.email, "INFO", request.POST.get('action'), json.dumps({"event": "GET_SHARED", "privileges": role, "message": f"Got shared."}), request.POST.get('client_sign'))    
        return JsonResponse([{'id':s.id, 'email':s.doctor.email} for s in shares], safe=False)
    except Exception as e:
        create_logs(request, "SYSTEM", "ERROR", "SHARE", json.dumps({"event": "GET_SHARED", "privileges": role, "message": f"Error while getting sharing info of file id: {fid}. Error: {e}"}), None)
        return JsonResponse([], safe=False)

# doctor views

def shared_folder_provider(request):
    user, role = get_logged_in_user(request)
    if role != 'doctor':
        return JsonResponse([], safe=False)
    
    if not verify_transaction(request, user, "PROVIDE"):
        create_logs(request, user.email, "WARNING", "REPLAY_ATTACK", "Invalid signature or timestamp.", None)
        return JsonResponse([], safe=False)
    
    shares = Shared.objects.filter(doctor=user)
    data = [] 
    for s in shares:
        data.append({
            'id': s.folder.id,
            'name': s.folder.name,
            'hmac_name': s.folder.hmac_name,
            'user': s.patient.email,
            'created_at': s.folder.created_at,
            'appointment_date': s.folder.appointment_date,
            'hmac_appointment_date': s.folder.hmac_appointment_date,
            'path': s.folder.path,
            'owner_id': s.patient.id
        })
    
    create_logs(request, user.email, "INFO", request.POST.get('action'), json.dumps({"event": "SHARED_FOLDER_PROVIDER", "privileges": role, "message": f"Got shared folder provider."}), request.POST.get('client_sign'))    
    return JsonResponse(data, safe=False)

def shared_file_provider(request):
    user, role = get_logged_in_user(request)
    fid = request.POST['folder_id']

    if not verify_transaction(request, user, "PROVIDE"):
        create_logs(request, user.email, "WARNING", "REPLAY_ATTACK", "Invalid signature or timestamp.", None)
        return JsonResponse([], safe=False)

    if Shared.objects.filter(doctor=user, folder_id=fid).exists():
        files = File.objects.filter(folder_id=fid).values()
        file_versions = File_version.objects.filter(folder_id=fid).values(
            'id', 'title', 'signed_title', 'uploaded_by__email', 'blob_url', 'size', 'signed_size', 'signed_blob', 'file__id'
        )
        create_logs(request, user.email, "INFO", request.POST.get('action'), json.dumps({"event": "SHARED_FILE_PROVIDER", "privileges": role, "message": f"{str(list(files).count)} shared file(s) provided."}), request.POST.get('client_sign'))    
        return JsonResponse(list(files) + list(file_versions), safe=False)
    return JsonResponse([], safe=False)

# notifications

def notifications(request):
    user, role = get_logged_in_user(request)
    notifs = Notification.objects.filter(reciever=user).order_by('-created_at')
    data = []
    for n in notifs:
        if is_notification_valid(n):     
            sender_email = n.sender.email if n.sender else "System"
            folder_id = n.shared.folder.id if n.shared and n.shared.folder else ""
            data.append({
                "id": n.id,
                "sender": sender_email,
                "shared_by": sender_email,
                "message": n.message,
                "folder": folder_id,
                "created_at": n.created_at
            })
    
    if role == 'patient':
        return render(request, 'notifications.html', {'notifications': data})
    else:
        return render(request, 'notifications_doctor.html', {'notifications': data})

def mark_notification_read(request):
    try:
        data = json.loads(request.body)
        nid = data.get('id')
        n = Notification.objects.get(id=nid)
        n.delete()
        return JsonResponse({'status': True})
    except Exception as e:
        create_logs(request, "SYSTEM", "ERROR", "MARK_NOTIFICATION", json.dumps({"event": "MARK_NOTIFICATION", "privileges": get_logged_in_user(request)[1], "message": f"Error while marking notification sharing: {e}"}), None)
        return JsonResponse({'status': False, 'error': 'Notification read failed!'})

def delete_notification(request):
    if request.method == 'POST':
        notification_id = request.POST.get('notification')
        user_id = request.session.get('user_id')

        if not notification_id or not user_id:
            return HttpResponse('Missing notification ID or user session.', status=400)

        try:
            notification = Notification.objects.get(id=notification_id)
            if (str(notification.sender_id) == str(user_id) or 
                str(notification.reciever_id) == str(user_id)):
                
                notification.delete()
                return HttpResponse('Notification deleted successfully.', status=200)
            else:
                return HttpResponse('Permission denied.', status=403)
                
        except Notification.DoesNotExist as e:
            create_logs(request, "SYSTEM", "ERROR", "DELETE_NOTIFICATION", json.dumps({"event": "DELETE_NOTIFICATION", "privileges": get_logged_in_user(request), "message": f"Error while deleting notification: {e}"}), None)
            return HttpResponse('Notification not found.', status=404)
            
    return HttpResponse('Method Not Allowed', status=405)

# others

def render_shared(request):
    if 'user_id' in request.session.keys() and request.session['user_id'] is not None:
        if request.GET and request.GET.__contains__('folder_id'):
            return render(request, 'shared.html', {'folder_id': request.GET['folder_id']})
        return render(request, 'shared.html')
    return redirect('index')

# misc

def vault(request):
    if request.session and request.session.__contains__('user_id'):
        obj = User.objects.get(id=int(request.session['user_id']))
        if obj:
            if obj.user_vault_psw == "":
                return redirect('profile')
    return redirect('vault_dashboard')

def auth_vault(request):
    if request.session and request.session.__contains__('user_id') and request.POST and request.POST.__contains__(
            'user_id') and request.POST.__contains__('password'):
        obj = User.objects.get(id=int(request.session['user_id']))
        if obj:
            hashed = hashlib.md5(request.POST['password'].encode())
            password = hashed.hexdigest()
            if obj.user_vault_psw == password:
                request.session['vault_auth'] = True
                return JsonResponse({'Status': True})
            else:
                return JsonResponse({'Status': False})

    return redirect('dashboard')

def get_current_user_data(request):
    """
    Récupère les données chiffrées de l'utilisateur connecté 
    pour permettre la vérification du mot de passe côté client.
    """
    # On utilise ta fonction existante ou request.user directement
    user, role = get_logged_in_user(request)
    
    if not user:
        return JsonResponse({'error': 'User not logged in'}, status=403)

    # On construit exactement l'objet attendu par handleProfile dans ton JS
    user_data = {
        'email': user.email,
        'hmac_email': user.hmac_email,
        'firstname': user.firstname,
        'hmac_firstname': user.hmac_firstname,
        'lastname': user.lastname,
        'hmac_lastname': user.hmac_lastname,
        
        # Clés cryptographiques
        'public_key': user.public_key,
        'private_key': user.private_key,
        'hmac_private_key': user.hmac_private_key,
        'encrypted_symmetric_key': user.encrypted_symmetric_key,
        'signed_symmetric_key': user.signed_symmetric_key,
        'encrypted_hmac_key': user.encrypted_hmac_key,
        'signed_hmac_key': user.signed_hmac_key,
    }

    # Ajout des champs optionnels selon le modèle
    if hasattr(user, 'birthdate') and user.birthdate:
        user_data['birthdate'] = user.birthdate
        user_data['hmac_birthdate'] = getattr(user, 'hmac_birthdate', '')
        
    if hasattr(user, 'organization') and user.organization:
        user_data['organization'] = user.organization
        user_data['hmac_organization'] = getattr(user, 'hmac_organization', '')

    return JsonResponse({'user_data': user_data})

def change_psw(request):
    """
    Met à jour la private_key et hmac_private_key de l'utilisateur
    après que le front-end a vérifié le mot de passe actuel et généré
    les nouvelles clés.
    """
    # Debug: voir ce qui est reçu
    print("[DEBUG] change_psw called")
    print("[DEBUG] Method:", request.method)
    print("[DEBUG] POST keys:", list(request.POST.keys()))
    
    for key in request.POST:
        value = request.POST[key]
        print(f"[DEBUG] {key}: {value[:50]}..." if len(value) > 50 else f"[DEBUG] {key}: {value}")
    # ⚡ Récupérer l'utilisateur connecté
    user, role = get_logged_in_user(request)
    if not user:
        return JsonResponse({"status": "error", "message": "User not logged in"}, status=403)

    # ⚡ Récupérer TOUTES les nouvelles clés
    new_priv = request.POST.get('new_private_key')
    new_hmac = request.POST.get('new_hmac_private_key')
    new_encrypted_symmetric_key = request.POST.get('new_encrypted_symmetric_key')
    new_signed_symmetric_key = request.POST.get('new_signed_symmetric_key')
    new_encrypted_hmac_key = request.POST.get('new_encrypted_hmac_key')
    new_signed_hmac_key = request.POST.get('new_signed_hmac_key')

    # Vérifier que toutes les clés sont présentes
    required_keys = [
        new_priv, new_hmac, 
        new_encrypted_symmetric_key, new_signed_symmetric_key,
        new_encrypted_hmac_key, new_signed_hmac_key
    ]
    
    if not all(required_keys):
        missing = []
        if not new_priv: missing.append('new_private_key')
        if not new_hmac: missing.append('new_hmac_private_key')
        if not new_encrypted_symmetric_key: missing.append('new_encrypted_symmetric_key')
        if not new_signed_symmetric_key: missing.append('new_signed_symmetric_key')
        if not new_encrypted_hmac_key: missing.append('new_encrypted_hmac_key')
        if not new_signed_hmac_key: missing.append('new_signed_hmac_key')
        
        return JsonResponse({
            "status": "error", 
            "message": f"Missing required keys: {', '.join(missing)}"
        }, status=400)

    # ⚡ Mettre à jour l'utilisateur
    try:
        user.private_key = new_priv
        user.hmac_private_key = new_hmac
        user.encrypted_symmetric_key = new_encrypted_symmetric_key
        user.signed_symmetric_key = new_signed_symmetric_key
        user.encrypted_hmac_key = new_encrypted_hmac_key
        user.signed_hmac_key = new_signed_hmac_key
        
        user.save()
        
        # Log de succès (optionnel)
        print(f"[DEBUG] Password changed successfully for user: {user.email}")
        
        return JsonResponse({
            "status": "ok",
            "message": "Password updated successfully"
        })
        
    except Exception as e:
        print(f"[ERROR] Failed to update user keys: {e}")
        return JsonResponse({
            "status": "error", 
            "message": f"Failed to update keys: {str(e)}"
        }, status=500)
        
        

def initiate_email_change(request):
    """
    ÉTAPE 1 : Reçoit le payload chiffré, le valide, 
    le stocke temporairement en SESSION et envoie l'OTP.
    """
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Invalid method'}, status=405)

    user, role = get_logged_in_user(request)
    if not user:
        return JsonResponse({'status': 'error', 'message': 'User not logged in'}, status=403)

    payload_str = request.POST.get('payload')
    if not payload_str:
        return JsonResponse({'status': 'error', 'message': 'No data received'}, status=400)

    try:
        data = json.loads(payload_str)
        
        # Validation de l'email
        new_email = validate_sanitize_email(data.get("email"))
        if not new_email:
            return JsonResponse({'status': 'error', 'message': 'Invalid email format'}, status=400)

        # Vérifier si l'email existe déjà
        if User.objects.filter(email=new_email).exists():
            return JsonResponse({'status': 'error', 'message': 'Email already exists'}, status=400)

        # Vérifier les clés crypto
        required_fields = ['hmac_email', 'private_key', 'hmac_private_key']
        if not all(k in data for k in required_fields):
             return JsonResponse({'status': 'error', 'message': 'Missing cryptographic data'}, status=400)

        # Générer l'OTP
        otp = str(random.randint(100000, 999999))
        
        # STOCKAGE EN SESSION (Important : on ne touche pas encore à la BDD User)
        request.session['pending_email_change'] = {
            'new_email': new_email,
            'payload': data, # On garde les clés rechiffrées au chaud
            'otp': otp,
            'attempts': 0
        }

        # Envoyer l'email
        try:
            send_email_func(new_email, "Confirm Email Change", f"Your verification code is: {otp}")
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': 'Failed to send verification email'}, status=500)
        
        return JsonResponse({'status': 'ok', 'message': 'OTP sent'})

    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON format'}, status=400)
    except Exception as e:
        print(f"[ERROR] Initiate email change failed: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)



def verify_email_change(request):
    """
    ÉTAPE 2 : Vérifie l'OTP entré par l'utilisateur.
    Si correct, applique les changements stockés en session.
    """
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Invalid method'}, status=405)

    user, role = get_logged_in_user(request)
    if not user:
        return JsonResponse({'status': 'error', 'message': 'User not logged in'}, status=403)

    # Récupérer les données en attente
    pending_data = request.session.get('pending_email_change')
    if not pending_data:
        return JsonResponse({'status': 'error', 'message': 'No pending email change request found or expired'}, status=400)

    user_otp = request.POST.get('otp')
    if not user_otp:
        return JsonResponse({'status': 'error', 'message': 'OTP is required'}, status=400)

    # Vérification OTP
    if str(pending_data['otp']).strip() != str(user_otp).strip():
        pending_data['attempts'] += 1
        request.session.modified = True
        
        if pending_data['attempts'] >= 3:
            del request.session['pending_email_change']
            return JsonResponse({'status': 'error', 'message': 'Too many failed attempts. Request cancelled.'}, status=400)
            
        return JsonResponse({'status': 'error', 'message': 'Invalid OTP'}, status=400)

    # SUCCÈS : Appliquer les changements en BDD
    try:
        payload = pending_data['payload']
        
        user.email = pending_data['new_email']
        user.hmac_email = payload['hmac_email']
        user.private_key = payload['private_key']
        user.hmac_private_key = payload['hmac_private_key']
        
        user.save()

        # Nettoyer la session
        del request.session['pending_email_change']

        print(f"[INFO] Email changed successfully for user ID {user.id}")
        return JsonResponse({'status': 'ok', 'message': 'Email updated successfully'})

    except Exception as e:
        return JsonResponse({'status': 'error', 'message': f"Database error: {str(e)}"}, status=500)

def change_profile(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Invalid method'}, status=405)

    user, role = get_logged_in_user(request)
    if not user:
        return JsonResponse({'status': 'error', 'message': 'User not logged in'}, status=403)

    # Données communes (Patient et Docteur)
    enc_firstname = request.POST.get('firstname')
    hmac_firstname = request.POST.get('hmac_firstname')
    enc_lastname = request.POST.get('lastname')
    hmac_lastname = request.POST.get('hmac_lastname')

    if not all([enc_firstname, hmac_firstname, enc_lastname, hmac_lastname]):
        return JsonResponse({'status': 'error', 'message': 'Missing name data'}, status=400)

    try:
        # Mise à jour Prénom / Nom
        user.firstname = enc_firstname
        user.hmac_firstname = hmac_firstname
        user.lastname = enc_lastname
        user.hmac_lastname = hmac_lastname

        # LOGIQUE SPÉCIFIQUE DOCTEUR (Organisation)
        if role == 'doctor':
            enc_org = request.POST.get('organization')
            hmac_org = request.POST.get('hmac_organization')
            
            if enc_org and hmac_org:
                user.organization = enc_org
                user.hmac_organization = hmac_org
            else:
                return JsonResponse({'status': 'error', 'message': 'Missing organization data'}, status=400)
        
        user.save()

        print(f"[INFO] Profile updated for {role} ID {user.id}")
        return JsonResponse({'status': 'ok', 'message': 'Profile updated'})

    except Exception as e:
        print(f"[ERROR] Update profile failed: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    

def setting(request):
    user, role = get_logged_in_user(request)
    if not user:
        return redirect('index')
    
    # On passe le 'role' au template pour savoir si on affiche le champ Organisation
    return render(request, 'profile.html', {'role': role})
def forgot_password(request):
    if User.objects.filter(email=request.POST['email']).count() > 0:
        temp_psw = str(random.randint(10000000,99999999))
        hashed = hashlib.md5(temp_psw.encode())
        password = hashed.hexdigest()
        userObj = User.objects.get(email=request.POST['email'])
        userObj.user_password = password
        userObj.save()
        send_email_func(request.POST['email'], "Reset Password", "Your new temporary password is: " + temp_psw + ". It is highly recommended to change your password from user profile :)</h4>")
        return JsonResponse({'status':True})
    return JsonResponse({'status':False})

def upload_files_doctor(request):
    user, role = get_logged_in_user(request)
    if not user or role != 'doctor':
        return JsonResponse({'status': False, 'error': "Permission Denied"})
    
    if not is_traffic_safe(request, user.email):
        return JsonResponse({'status': False, 'error': "Traffic limit exceeded. Action blocked."})

    if not verify_transaction(request, user, "MANAGE"):
        create_logs(request, user.email, "WARNING", "REPLAY_ATTACK", "Invalid signature or timestamp.", None)
        return JsonResponse({'status': False, 'error': "Request timeout."})

    try:
        folder_id = int(request.POST['parent_id'])
        if not folder_id: raise Exception("Missing folder ID")

        share = Shared.objects.get(folder_id=folder_id, doctor_id=user.id)
        
        file_count = int(request.POST.get('file_count', 0))
        count = 0

        for i in range(file_count):
            # Extract indexed data from POST and FILES
            encrypted_file = request.FILES.get(f'file_{i}')
            encrypted_size = request.POST.get(f'size_{i}')
            signed_name = request.POST.get(f'signed_name_{i}')
            signed_blob = request.POST.get(f'signed_blob_{i}')
            signed_size = request.POST.get(f'signed_size_{i}')

            if not encrypted_file:
                continue

            safe_filename = get_safe_filename(encrypted_file.name)
            safe_folder_name = get_safe_filename(json.loads(share.folder.name).get('encrypted_data'))

            relative_path = os.path.join(str(user.id), safe_folder_name, safe_filename)
            file_name = default_storage.save(relative_path, encrypted_file)
            file_url = default_storage.url(file_name)
            file = File.objects.get(id=request.POST.get(f'file_id_{i}'))

            File_version.objects.create(
                folder_id=share.folder.id,
                title=safe_filename,
                signed_title=signed_name,
                signed_blob=signed_blob,
                file=file,
                size=encrypted_size,
                signed_size=signed_size,
                uploaded_by=user,
                blob_url=file_url
            )
            Notification.objects.create(
                sender=user,
                reciever=share.patient,
                shared=share,
                message=f'A request file from doctor {user.email} have been added for the folder {share.folder.id}.'
            )
            count += 1
        
        return JsonResponse({'status': 'success', 'count': count})
    
    except Exception as e:
        create_logs(request, "SYSTEM", "ERROR", "UPLOAD_FILE_DOCTOR", json.dumps({"event": "UPLOAD_FILE_DOCTOR", "privileges": role, "message": f"Error while uploading file(s) as doctor: {e}"}), None)
        return JsonResponse({'status': False, 'error': str(e)})