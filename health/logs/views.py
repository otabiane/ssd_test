import re, hashlib, json
from datetime import timedelta
from django.utils import timezone
from django.http import JsonResponse
from django.db import models
from django.core.mail import send_mail
from django.conf import settings
from .models import LogEntry

def send_alert(subject, message):
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [settings.ALERT_RECIEVER_EMAIL],
            fail_silently=False
        )
    except Exception as e:
        create_logs(None, "SYSTEM", "ERROR", "SEND_EMAIL", json.dumps({"event": "SEND_EMAIL", "privileges": "SYSTEM", "message": f"Error while sending email to {settings.ALERT_RECIEVER_EMAIL}: {e}"}), None)
    

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def sanitize_log_input(text):
    if not text: return ""

    clean_text = re.sub(r'[\r\n]+', ' ', text)
    clean_text = clean_text.replace('\t', ' ').replace('%', '%25').replace('|', r'\|')
    clean_text = re.sub(r'[<>]', ' ', clean_text)

    clean_text = re.sub(r'(password|token|secret|key|credential)(\s*[:=]\s*)[^\s]+', r'\1\2******', clean_text, flags=re.I)

    return clean_text

def create_logs(request, user_identity, level, action, message, client_sign=None): 
    try:
        ip = get_client_ip(request)
        clean_msg = sanitize_log_input(message)
        clean_level = sanitize_log_input(level)
        clean_action = sanitize_log_input(action) 

        LogEntry.objects.create(
            user_identity=user_identity,
            level=clean_level,
            action=clean_action,
            message=clean_msg,
            ip_address=ip,
            client_sign=client_sign
        )
    except Exception as e:
        print(f"CRITICAL LOGGING FAILURE: {e}")

def is_traffic_safe(request, user_email):
    ip = get_client_ip(request)
    threshold = 30 # Max sensitive actions per minute

    if not ip and not user_email: return False
    
    count = LogEntry.objects.filter(
        created_at__gte=timezone.now() - timedelta(minutes=1)
    ).filter(
        models.Q(user_identity=user_email) | models.Q(ip_address=ip)
    ).count()

    if count > threshold:
        create_logs(request, "SYSTEM", "WARNING", "AUTO_BLOCK", f"Blocked IP {ip} for velocity", None)
        send_alert("Excesive actions detected", f"User: {user_email} with ip: {ip} was blocked dues to excessive actions per minute.")
        return False
    return True

def integrity_check(request):
    if request.session.get('user_id') != 1: return JsonResponse({'error': 'Unauthorized'})

    logs = LogEntry.objects.order_by('id')
    previous_hash = "0" * 64
    errors = []

    for log in logs:
        if log.previous_hash != previous_hash:
            errors.append(f"BROKEN CHAIN at ID: {log.id}.  Previous hash mismatch.")
        
        data_string = f"{log.created_at.isoformat()}{log.user_identity}{log.level}{log.action}{log.message}{log.client_sign}{log.previous_hash}"
        cal_hash = hashlib.sha256(data_string.encode('utf-8')).hexdigest()

        if cal_hash != log.current_hash:
            errors.append(f"DATA CORRUPTION at ID: {log.id}. Content does not match hash.")
            send_alert("Log data corrupted", f"Log data corrupted at ID: {log.id}.")

        previous_hash = log.current_hash
    
    status = "SECURE" if not errors else "COMPROMISED"
    return JsonResponse({"status": status, "total_logs_scanned": logs.count(), "errors": errors})