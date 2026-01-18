from django.db import models, transaction
from django.utils import timezone
from django.conf import settings
import sys, os, hmac, hashlib, json

def hmac_data(data, salt=None):
    if not data: return "", ""
    if salt is None: salt = os.urandom(16).hex() 
    
    data_str = str(data)
    digest = hmac.new(
        (settings.HMAC_KEY + salt).encode('utf-8'),
        data_str.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return json.dumps({"hmac": digest, "salt": salt})

def default_created_at():
    return timezone.now()

class LogEntry(models.Model):
    user_identity = models.EmailField()
    hmac_user_identity = models.CharField(max_length=500, blank=True)

    level = models.CharField(max_length=10)
    hmac_level = models.CharField(max_length=500, blank=True)

    action = models.CharField(max_length=50)
    hmac_action = models.CharField(max_length=500, blank=True)

    message = models.TextField()
    hmac_message = models.CharField(max_length=500, blank=True)

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    hmac_ip_address = models.CharField(max_length=500, blank=True)

    created_at = models.DateTimeField(default=default_created_at)
    hmac_created_at = models.CharField(max_length=500, blank=True)

    client_sign = models.TextField(blank=True, null=True) # non-repudation

    # integrity, hash chain
    previous_hash = models.CharField(max_length=64, default="0"*64)
    current_hash = models.CharField(max_length=64, blank=True)

    record_size = models.IntegerField(default=0)
    hmac_record_size = models.CharField(max_length=500, blank=True)

    def calculate_chain_hash(self):
        """
        Calculates the hash of THIS entry with the PREVIOUS entry's hash, creating a chain
        """
        data_string = f"{self.created_at.isoformat()}{self.user_identity}{self.level}{self.action}{self.message}{self.client_sign}{self.previous_hash}"
        return hashlib.sha256(data_string.encode('utf-8')).hexdigest()
    
    def save(self, *args, **kwargs):
        self.hmac_user_identity = hmac_data(self.user_identity)
        self.hmac_level = hmac_data(self.level)
        self.hmac_action = hmac_data(self.action)
        self.hmac_message = hmac_data(self.message)
        self.hmac_ip_address = hmac_data(self.ip_address)
        self.hmac_created_at = hmac_data(self.created_at.isoformat())
        self.record_size = sys.getsizeof(self)
        self.hmac_record_size = hmac_data(self.record_size)

        # apply hash chaining
        if not self.pk:
            with transaction.atomic():
                last_entry = LogEntry.objects.select_for_update().order_by('id').last()
                if last_entry:
                    self.previous_hash = last_entry.current_hash
                else:
                    self.previous_hash = "0" * 64
            
                self.current_hash = self.calculate_chain_hash()

                super().save(*args, **kwargs)
        else:
            super().save(*args, **kwargs)

    def __str__(self):
        return f"[{self.created_at} - {self.level}] {self.user_identity}: {self.message}"

    class Meta:
        verbose_name = "Log Entry"