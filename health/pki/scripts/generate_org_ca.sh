#!/usr/bin/env bash
set -euo pipefail

ORG_NAME="${1:-}"
ROOT_CRT="${2:-}"
ROOT_KEY="${3:-}"
OUT_DIR="${4:-.}"

if [[ -z "$ORG_NAME" ]]; then
  echo "ERROR: Missing ORG_NAME. Example: ./generate_org_ca.sh \"HospitalA\" root_ca.crt root_ca.key org_ca"
  exit 1
fi

for f in "$ROOT_CRT" "$ROOT_KEY"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: File not found: $f"
    exit 1
  fi
done

mkdir -p "$OUT_DIR"

KEY_OUT="$OUT_DIR/${ORG_NAME}_ca.key"
CSR_OUT="$OUT_DIR/${ORG_NAME}_ca.csr"
CRT_OUT="$OUT_DIR/${ORG_NAME}_ca.crt"
EXT_OUT="$OUT_DIR/${ORG_NAME}_ca_ext.cnf"
SER_OUT="$OUT_DIR/root_ca.srl"

# Extensions required for an intermediate CA certificate
cat > "$EXT_OUT" <<'EOF'
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

echo "[1/5] Generating Org CA private key..."
openssl genrsa -out "$KEY_OUT" 4096

echo "[2/5] Creating CSR for Org CA..."
# Keep subject simple; add more DN fields if you want (O=, C=, etc.)
openssl req -new -key "$KEY_OUT" -out "$CSR_OUT" -subj "/CN=${ORG_NAME}"

echo "[3/5] Signing Org CA certificate with Root CA..."
# -CAcreateserial creates root_ca.srl (serial file); we keep it in OUT_DIR for reproducibility
openssl x509 -req -in "$CSR_OUT" \
  -CA "$ROOT_CRT" -CAkey "$ROOT_KEY" \
  -CAcreateserial -CAserial "$SER_OUT" \
  -out "$CRT_OUT" -days 3650 -sha256 \
  -extfile "$EXT_OUT"

echo "[4/5] Verifying that Org CA chains to Root CA..."
openssl verify -CAfile "$ROOT_CRT" "$CRT_OUT"

echo "[5/5] Showing CA-relevant extensions (should include CA:TRUE and keyCertSign)..."
openssl x509 -in "$CRT_OUT" -noout -subject -issuer -dates -fingerprint -sha256
echo
openssl x509 -in "$CRT_OUT" -noout -text | sed -n '/Basic Constraints/,+6p'
echo
openssl x509 -in "$CRT_OUT" -noout -text | sed -n '/Key Usage/,+6p'

echo
echo "DONE ✅"
echo "Org CA cert: $CRT_OUT"
echo "Org CA key : $KEY_OUT"
