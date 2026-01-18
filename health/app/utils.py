import os, hmac, hashlib, json
from django.conf import settings
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.utils.html import escape
from django.core.mail import send_mail  # <--- AJOUT IMPORTANT
from .models import Patient, Doctor

#--- Crypto helpers
def hmac_data(data, salt=None):
    if not data:
        return "", ""
    
    if salt is None:
        salt = os.urandom(16).hex() 
    
    data_str = str(data)
    
    digest = hmac.new(
        (settings.HMAC_KEY + salt).encode('utf-8'),
        data_str.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return json.dumps({"hmac": digest, "salt": salt})

def is_hmac_correct(hmac_output, data):
    try:
        data_str = str(data)
        output = json.loads(hmac_output)
        tmp_hmac = hmac.new(
            (settings.HMAC_KEY + output["salt"]).encode('utf-8'),
            data_str.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return tmp_hmac == output["hmac"]
    except:
        return False

# --- Email helpers (AJOUTÉ)
def send_email_func(mail, subject, message):
    """
    Wrapper pour envoyer des emails via Django
    """
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [mail],
            fail_silently=False
        )
        return True
    except Exception as e:
        # Idéalement, ajoutez un logger ici
        print(f"[ERROR] Failed to send email to {mail}: {e}")
        return False

# --- User helpers
def get_logged_in_user(request):
    uid = request.session.get('user_id')
    if not uid:
        return None, None
    
    try:
        return Patient.objects.get(id=uid), 'patient'
    except Patient.DoesNotExist:
        pass
        
    try:
        return Doctor.objects.get(id=uid), 'doctor'
    except Doctor.DoesNotExist:
        pass
    
    return None, None

def get_user_by_email(email):
    if not email: return None, None

    try:
        return Patient.objects.get(email=email), 'patient'
    except Patient.DoesNotExist:
        pass

    try:
        return Doctor.objects.get(email=email), 'doctor'
    except Doctor.DoesNotExist:
        return None, None
    
def get_user_by_id(id):
    if not id: return None, None

    try:
        return Patient.objects.get(id=id), 'patient'
    except Patient.DoesNotExist: pass

    try:
        return Doctor.objects.get(id=id), 'doctor'
    except: 
        return None, None
    
# Input sanitization
def sanitize_str(input):
    """
    removes whitespaces and HTML-espaces characters
    """
    if not input:
        return None
    
    return escape(str(input).strip())

def validate_sanitize_email(email):
    """
    validates email format and sanitize it
    """
    clean_email = sanitize_str(email)
    if not clean_email:
        return None
        
    try:
        validate_email(clean_email)
        return clean_email.lower()
    except ValidationError:
        return None
    
def get_safe_filename(filename):
    """
    prevents directory traversal
    returns just the basename of the file.
    """
    if not filename:
        return "unknown_file"
    return os.path.basename(filename)