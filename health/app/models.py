from django.db import models
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
import os, hmac, hashlib, json, sys

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
    data_str = str(data)
    output = json.loads(hmac_output)
    tmp_hmac = hmac.new(
        (settings.HMAC_KEY + output["salt"]).encode('utf-8'),
        data_str.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return tmp_hmac == output["hmac"]

def default_created_at():
    return timezone.now() + timedelta(minutes=0)

def default_expiration_time():
    return timezone.now() + timedelta(minutes=1)

class User(models.Model):
    email = models.EmailField(unique=True)
    hmac_email = models.CharField(max_length=500)
    firstname = models.CharField(max_length=500)
    hmac_firstname = models.CharField(max_length=500)
    lastname = models.CharField(max_length=500)
    hmac_lastname = models.CharField(max_length=500)
    created_at = models.DateTimeField(default=default_created_at)
    hmac_created_at = models.CharField(max_length=500, blank=True)

    record_size = models.IntegerField(default=0)
    hmac_record_size = models.CharField(max_length=500, blank=True)
    
    encrypted_symmetric_key = models.CharField(max_length=500)
    signed_symmetric_key = models.CharField(max_length=500)
    encrypted_hmac_key = models.CharField(max_length=500)
    signed_hmac_key = models.CharField(max_length=500)
    public_key = models.CharField(max_length=500)
    private_key = models.CharField(max_length=3000)
    hmac_private_key = models.CharField(max_length=500)
    
    def __str__(self):
        return self.email
    
    def save(self, *args, **kwargs):
        self.hmac_created_at = hmac_data(self.created_at.isoformat())
        self.record_size = sys.getsizeof(self)
        self.hmac_record_size = hmac_data(self.record_size)
        super().save(*args, **kwargs)

class Patient(User):
    birthdate = models.CharField(max_length=500)
    hmac_birthdate = models.CharField(max_length=500)
    
class Doctor(User):
    organization = models.CharField(max_length=500)
    hmac_organization = models.CharField(max_length=500)

    # PKI (X.509) certificate for doctors
    certificate = models.TextField(blank=True)  # PEM
    hmac_certificate = models.CharField(max_length=500, blank=True)
    cert_not_before = models.DateTimeField(null=True, blank=True)
    cert_not_after = models.DateTimeField(null=True, blank=True)

    def save(self, *args, **kwargs):
        # Don't overwrite client-generated hmac_organization.
        if self.organization and not self.hmac_organization:
            self.hmac_organization = hmac_data(self.organization)

        # Compute HMAC for certificate if it's present and not set.
        if self.certificate and not self.hmac_certificate:
            self.hmac_certificate = hmac_data(self.certificate)

        super().save(*args, **kwargs)

class Verification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    hmac_otp = models.CharField(max_length=500)
    created_at = models.DateTimeField(default=default_created_at)
    hmac_created_at = models.CharField(max_length=500, blank=True)
    record_size = models.IntegerField(default=0)
    hmac_record_size = models.CharField(max_length=500, blank=True)
    expires_at = models.DateTimeField(default=default_expiration_time)
    hmac_expires_at = models.CharField(max_length=500)
    
    def save(self, *args, **kwargs):
        self.hmac_otp = hmac_data(self.otp)
        self.hmac_created_at = hmac_data(self.created_at.isoformat())
        self.hmac_expires_at = hmac_data(self.expires_at.isoformat())
        self.record_size = sys.getsizeof(self)
        self.hmac_record_size = hmac_data(self.record_size)
        super().save(*args, **kwargs)

class Folder(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=500)
    hmac_name = models.CharField(max_length=500)
    appointment_date = models.CharField(max_length=500)
    hmac_appointment_date = models.CharField(max_length=500)
    created_at = models.DateTimeField(default=default_created_at)
    hmac_created_at = models.CharField(max_length=500, blank=True)
    record_size = models.IntegerField(default=0)
    hmac_record_size = models.CharField(max_length=500, blank=True)
    path = models.TextField(max_length=500, blank=True)
    hmac_path = models.TextField(max_length=500)
    encrypted_symmetric_key = models.CharField(max_length=500)
    signed_symmetric_key = models.CharField(max_length=500)
    encrypted_hmac_key = models.CharField(max_length=500)
    signed_hmac_key = models.CharField(max_length=500)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        self.hmac_created_at = hmac_data(self.created_at.isoformat())
        self.record_size = sys.getsizeof(self)
        self.hmac_record_size = hmac_data(self.record_size)
        self.hmac_path = hmac_data(self.path)
        super().save(*args, **kwargs)

class File(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="owner")
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, null=True, blank=True)
    title = models.CharField(max_length=500)
    hmac_title = models.CharField(max_length=500)
    hmac_file = models.CharField(max_length=500, blank=True)
    size = models.CharField(max_length=500)
    hmac_size = models.CharField(max_length=500)
    upload_date = models.DateTimeField(auto_now_add=True)
    hmac_upload_date = models.CharField(max_length=500, blank=True)
    link = models.TextField(max_length=500)
    hmac_link = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(default=default_created_at)
    hmac_created_at = models.CharField(max_length=500, blank=True)
    record_size = models.IntegerField(default=0)
    hmac_record_size = models.CharField(max_length=500, blank=True)

    def __str__(self):
        return self.title
    
    def save(self, *args, **kwargs):
        self.hmac_created_at = hmac_data(self.created_at.isoformat())
        self.record_size = sys.getsizeof(self)
        self.hmac_record_size = hmac_data(self.record_size)
        self.hmac_upload_date = hmac_data(self.upload_date)
        self.hmac_link = hmac_data(self.link)
        super().save(*args, **kwargs)

class Shared(models.Model):
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='shared_by')
    doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE, null=True, blank=True, related_name='shared_with')
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, null=True, blank=True)
    created_at = models.DateTimeField(default=default_created_at)
    hmac_created_at = models.CharField(max_length=500, blank=True)
    record_size = models.IntegerField(default=0)
    hmac_record_size = models.CharField(max_length=500, blank=True)
    
    encrypted_symmetric_key = models.CharField(max_length=500)#signed with public key of doctor
    signed_symmetric_key = models.CharField(max_length=500)#signed with privated key of patient
    encrypted_hmac_key = models.CharField(max_length=500)
    signed_hmac_key = models.CharField(max_length=500)

    def __str__(self):
        return f"{self.patient} -> {self.doctor}"
    
    def save(self, *args, **kwargs):
        self.hmac_created_at = hmac_data(self.created_at.isoformat())
        self.record_size = sys.getsizeof(self)
        self.hmac_record_size = hmac_data(self.record_size)
        super().save(*args, **kwargs)

class Notification(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sender")
    reciever = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name="reciever")
    shared = models.ForeignKey(Shared, on_delete=models.CASCADE, null=True, blank=True)
    message = models.CharField(max_length=255)
    hmac_message = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(default=default_created_at)
    hmac_created_at = models.CharField(max_length=500, blank=True)
    record_size = models.IntegerField(default=0)
    hmac_record_size = models.CharField(max_length=500, blank=True)
    
    def save(self, *args, **kwargs):
        self.hmac_created_at = hmac_data(self.created_at.isoformat())
        self.record_size = sys.getsizeof(self)
        self.hmac_record_size = hmac_data(self.record_size)
        self.hmac_message = hmac_data(self.message)
        super().save(*args, **kwargs)

class Challenge(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    challenge = models.CharField(max_length=500)
    hmac_challenge = models.CharField(max_length=500)
    created_at = models.DateTimeField(default=default_created_at)
    hmac_created_at = models.CharField(max_length=500, blank=True)
    record_size = models.IntegerField(default=0)
    hmac_record_size = models.CharField(max_length=500, blank=True)
    expires_at = models.DateTimeField(default=default_expiration_time)
    hmac_expires_at = models.CharField(max_length=500, blank=True)
    
    def save(self, *args, **kwargs):
        self.hmac_challenge = hmac_data(self.challenge)
        self.hmac_created_at = hmac_data(self.created_at.isoformat())
        self.hmac_expires_at = hmac_data(self.expires_at.isoformat())
        self.record_size = sys.getsizeof(self)
        self.hmac_record_size = hmac_data(self.record_size)
        super().save(*args, **kwargs)


class File_version(models.Model):
    title = models.CharField(max_length=500)
    signed_title = models.CharField(max_length=500)
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, null=True, blank=True)
    signed_blob = models.CharField(max_length=500)
    blob_url = models.CharField(max_length=500)
    hmac_blob_url = models.CharField(max_length=500, blank=True)
    file = models.ForeignKey(File, on_delete=models.CASCADE, blank=True, null=True)
    size = models.CharField(max_length=500)
    signed_size = models.CharField(max_length=500)
    uploaded_by = models.ForeignKey(Doctor, on_delete=models.CASCADE, null=True, blank=True, related_name="uploaded_by")
    created_at = models.DateTimeField(default=default_created_at)
    hmac_created_at = models.CharField(max_length=500, blank=True)
    record_size = models.IntegerField(default=0)
    hmac_record_size = models.CharField(max_length=500, blank=True)

    def __str__(self):
        return self.title
    
    def save(self, *args, **kwargs):
        self.hmac_created_at = hmac_data(self.created_at.isoformat())
        self.record_size = sys.getsizeof(self)
        self.hmac_record_size = hmac_data(self.record_size)
        self.hmac_blob_url = hmac_data(self.blob_url)
        super().save(*args, **kwargs)