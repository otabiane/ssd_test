from pathlib import Path
from django.conf import settings
from app.pki.check_ca import verify_doctor_certificate, verify_doctor_login, PKIError

# Chemin vers le certificat docteur
doctor_cert_path = Path(settings.PKI_DIR) / "doctors" / "drsmith.crt"
doctor_key_path = Path(settings.PKI_DIR) / "doctors" / "drsmith.key"

with open(doctor_cert_path, "r") as f:
    doctor_cert_pem = f.read()

with open(doctor_key_path, "r") as f:
    doctor_key_pem = f.read()

# Test de vérification du certificat
try:
    org_name = verify_doctor_certificate(doctor_cert_pem)
    print(f"✅ Certificat valide pour l'organisation: {org_name}")
except PKIError as e:
    print(f"❌ Erreur de certificat: {e}")

# Test de login (signature d'un challenge)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
import os

challenge = os.urandom(32)  # challenge aléatoire

# Charger la clé privée du docteur
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

private_key = serialization.load_pem_private_key(
    doctor_key_pem.encode(),
    password=None,
    backend=default_backend()
)

# Signer le challenge
signature = private_key.sign(
    challenge,
    padding.PKCS1v15(),
    hashes.SHA256()
)

# Simuler objet doctor avec attribut certificate
class Doctor:
    certificate = doctor_cert_pem

doctor = Doctor()

# Vérifier signature
try:
    verify_doctor_login(doctor, signature, challenge)
    print("✅ Login challenge validé")
except PKIError as e:
    print(f"❌ Login challenge invalide: {e}")
