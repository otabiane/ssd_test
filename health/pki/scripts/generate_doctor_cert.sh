#!/usr/bin/env bash
set -euo pipefail

DOC_CN="${1:-}"
ORG_NAME="${2:-}"
ORG_CRT="${3:-}"
ORG_KEY="${4:-}"
ROOT_CRT="${5:-}"
OUT_DIR="${6:-.}"

if [[ -z "$DOC_CN" || -z "$ORG_NAME" ]]; then
  echo "ERROR: Missing args."
  echo "Example: ./generate_doctor_cert.sh \"drsmith\" \"HospitalA\" org_ca.crt org_ca.key root_ca.crt doctors_dir"
  exit 1
fi

for f in "$ORG_CRT" "$ORG_KEY" "$ROOT_CRT"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: File not found: $f"
    exit 1
  fi
done

mkdir -p "$OUT_DIR"

KEY_OUT="$OUT_DIR/${DOC_CN}.key"
CSR_OUT="$OUT_DIR/${DOC_CN}.csr"
CRT_OUT="$OUT_DIR/${DOC_CN}.crt"
EXT_OUT="$OUT_DIR/${DOC_CN}_ext.cnf"
SER_OUT="$OUT_DIR/${ORG_NAME}_ca.srl"

# End-entity (doctor) cert extensions
# - CA:FALSE is mandatory
# - keyUsage digitalSignature is typical for signing challenges
# - extendedKeyUsage clientAuth is recommended if you treat it as a client certificate
cat > "$EXT_OUT" <<'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

echo "[1/6] Generating doctor private key..."
openssl genrsa -out "$KEY_OUT" 4096

echo "[2/6] Creating CSR for doctor..."
# Subject includes CN=doctor and O=org (helpful but optional)
openssl req -new -key "$KEY_OUT" -out "$CSR_OUT" -subj "/CN=${DOC_CN}/O=${ORG_NAME}"

echo "[3/6] Signing doctor certificate with Org CA..."
# -CAcreateserial creates serial file; we keep a stable filename per org in OUT_DIR
openssl x509 -req -in "$CSR_OUT" \
  -CA "$ORG_CRT" -CAkey "$ORG_KEY" \
  -CAcreateserial -CAserial "$SER_OUT" \
  -out "$CRT_OUT" -days 365 -sha256 \
  -extfile "$EXT_OUT"

echo "[4/6] Verifying doctor cert chain (Root <- Org <- Doctor)..."
openssl verify -CAfile "$ROOT_CRT" -untrusted "$ORG_CRT" "$CRT_OUT"

echo "[5/6] Checking certificate/key match..."
# For RSA keys, modulus hash should match
openssl x509 -noout -modulus -in "$CRT_OUT" | openssl md5 > /tmp/doc_cert_md5.txt
openssl rsa  -noout -modulus -in "$KEY_OUT" | openssl md5 > /tmp/doc_key_md5.txt
diff -q /tmp/doc_cert_md5.txt /tmp/doc_key_md5.txt >/dev/null
echo "OK: doctor cert matches private key."

echo "[6/6] Showing key certificate properties..."
openssl x509 -in "$CRT_OUT" -noout -subject -issuer -dates -fingerprint -sha256
echo
openssl x509 -in "$CRT_OUT" -noout -text | sed -n '/Basic Constraints/,+6p'
echo
openssl x509 -in "$CRT_OUT" -noout -text | sed -n '/Key Usage/,+6p'
echo
openssl x509 -in "$CRT_OUT" -noout -text | sed -n '/Extended Key Usage/,+6p'

echo
echo "DONE ✅"
echo "Doctor cert: $CRT_OUT"
echo "Doctor key : $KEY_OUT"
