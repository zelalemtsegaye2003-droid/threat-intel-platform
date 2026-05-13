# Generate self-signed certificate for development
# Run: bash scripts/generate-self-signed-cert.sh

set -e

CERT_DIR="nginx/ssl"
mkdir -p "$CERT_DIR"

echo "🔐 Generating self-signed certificate..."

openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout "$CERT_DIR/tls.key" \
  -out "$CERT_DIR/tls.crt" \
  -subj "/CN=localhost/O=ThreatIntelPlatform/C=US" 2>/dev/null

echo "✅ Certificate generated at $CERT_DIR/"
echo "   tls.crt — public certificate"
echo "   tls.key — private key (keep secret!)"