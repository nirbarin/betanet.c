#!/bin/bash
# Script to generate test certificates for TCP/TLS testing

set -e  # Exit on error

# Create directory for certificates
CERT_DIR="$(dirname "$0")"
echo "Generating test certificates in $CERT_DIR"

# Remove any existing certificates
rm -f "$CERT_DIR"/ca.key "$CERT_DIR"/ca.crt
rm -f "$CERT_DIR"/server.key "$CERT_DIR"/server.csr "$CERT_DIR"/server.crt
rm -f "$CERT_DIR"/client.key "$CERT_DIR"/client.csr "$CERT_DIR"/client.crt

# Create CA certificate
echo "Generating CA certificate..."
openssl genrsa -out "$CERT_DIR"/ca.key 2048
openssl req -new -x509 -days 3650 -key "$CERT_DIR"/ca.key -out "$CERT_DIR"/ca.crt \
    -subj "/CN=Test CA/O=Betanet Test/C=US"

# Create server certificate
echo "Generating server certificate..."
openssl genrsa -out "$CERT_DIR"/server.key 2048
openssl req -new -key "$CERT_DIR"/server.key -out "$CERT_DIR"/server.csr \
    -subj "/CN=localhost/O=Betanet Test Server/C=US"
openssl x509 -req -days 3650 -in "$CERT_DIR"/server.csr -CA "$CERT_DIR"/ca.crt \
    -CAkey "$CERT_DIR"/ca.key -CAcreateserial -out "$CERT_DIR"/server.crt

# Create client certificate
echo "Generating client certificate..."
openssl genrsa -out "$CERT_DIR"/client.key 2048
openssl req -new -key "$CERT_DIR"/client.key -out "$CERT_DIR"/client.csr \
    -subj "/CN=Betanet Test Client/O=Betanet Test Client/C=US"
openssl x509 -req -days 3650 -in "$CERT_DIR"/client.csr -CA "$CERT_DIR"/ca.crt \
    -CAkey "$CERT_DIR"/ca.key -CAcreateserial -out "$CERT_DIR"/client.crt

# Clean up CSR files
rm -f "$CERT_DIR"/server.csr "$CERT_DIR"/client.csr "$CERT_DIR"/ca.srl

echo "Certificate generation complete."
echo "Generated files:"
echo "  CA certificate:     $CERT_DIR/ca.crt"
echo "  Server certificate: $CERT_DIR/server.crt"
echo "  Server key:         $CERT_DIR/server.key"
echo "  Client certificate: $CERT_DIR/client.crt"
echo "  Client key:         $CERT_DIR/client.key"