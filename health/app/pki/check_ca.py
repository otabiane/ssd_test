from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import Certificate
from datetime import datetime, timezone
from pathlib import Path
from django.conf import settings
from .exceptions import PKIError


def verify_chain(cert: Certificate, org_ca_cert: Certificate, root_ca_cert: Certificate):
    """
    Vérifie la chaîne complète : Doctor -> Org CA -> Root CA
    """
    # Vérification signature Doctor -> Org CA
    try:
        org_ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    except Exception as e:
        raise PKIError(f"Doctor certificate not signed by Org CA: {e}")

    # Vérification signature Org CA -> Root CA
    try:
        root_ca_cert.public_key().verify(
            org_ca_cert.signature,
            org_ca_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            org_ca_cert.signature_hash_algorithm
        )
    except Exception as e:
        raise PKIError(f"Org CA not signed by Root CA: {e}")


def verify_doctor_certificate(cert_pem: str) -> str:
    """
    Vérifie le certificat du docteur :
    - Encodage UTF-8
    - Chaîne complète Root CA → Org CA → Doctor
    - Vérifie la validité temporelle avec timezone-aware
    Retourne le nom de l'organisation
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
    except Exception as e:
        raise PKIError(f"Invalid certificate format: {e}")

    # Vérification de validité temporelle
    try:
        not_before = cert.not_valid_before_utc
        not_after  = cert.not_valid_after_utc
    except AttributeError:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after  = cert.not_valid_after.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)

    if not_before > now or not_after < now:
        raise PKIError("Doctor Certificate expired or not yet valid")

    # Extraction organisation ou fallback CN
    org_attr = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    org = org_attr[0].value.strip() if org_attr else None
    if not org:
        cn_attr = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        org = cn_attr[0].value.strip() if cn_attr else None
        if not org:
            raise PKIError("Certificate missing organization and CN")

    # Charger CA de l'organisation
    org_ca_path = Path(settings.TRUSTED_ORG_CA_DIR) / f"{org}_ca.crt"
    if not org_ca_path.exists():
        raise PKIError(f"Unknown organization CA: {org}")

    try:
        with open(org_ca_path, "rb") as f:
            org_ca_cert = x509.load_pem_x509_certificate(f.read())
    except Exception as e:
        raise PKIError(f"Failed to load Org CA certificate: {e}")

    # Charger Root CA
    root_ca_path = Path(settings.TRUSTED_ROOT_CA)
    if not root_ca_path.exists():
        raise PKIError("Root CA certificate not found")
    try:
        with open(root_ca_path, "rb") as f:
            root_ca_cert = x509.load_pem_x509_certificate(f.read())
    except Exception as e:
        raise PKIError(f"Failed to load Root CA certificate: {e}")

    # Vérifier toute la chaîne
    verify_chain(cert, org_ca_cert, root_ca_cert)

    return org

def verify_doctor_login(doctor, signature: bytes, challenge: bytes):
    try:
        cert = x509.load_pem_x509_certificate(doctor.certificate.encode('utf-8'))
    except Exception as e:
        raise PKIError(f"Invalid doctor certificate format: {e}")

    try:
        cert.public_key().verify(
            signature,
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32,   # MUST match frontend
            ),
            hashes.SHA256()
        )
    except Exception as e:
        raise PKIError(f"Invalid signature for login challenge: {e}")
