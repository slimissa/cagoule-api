#!/usr/bin/env bash
# gen_certs.sh — Génération de certificats self-signed pour mTLS cagoule-api
# Usage : bash scripts/gen_certs.sh
# Sortie : certs/ca.crt, certs/server.{key,crt}, certs/client.{key,crt}

set -euo pipefail

CERTS_DIR="$(dirname "$0")/../certs"
mkdir -p "$CERTS_DIR"

SUBJ_CA="/C=TN/ST=Kairouan/O=QuantOS/CN=CagouleCA"
SUBJ_SRV="/C=TN/ST=Kairouan/O=QuantOS/CN=cagoule-api-server"
SUBJ_CLI="/C=TN/ST=Kairouan/O=QuantOS/CN=cagoule-api-client"

echo "──────────────────────────────────"
echo "  cagoule-api — Génération mTLS"
echo "  AVERTISSEMENT : Certificats académiques"
echo "  Ne pas utiliser en production."
echo "──────────────────────────────────"

# 1. CA auto-signé
echo "[1/3] Génération CA..."
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
  -keyout "$CERTS_DIR/ca.key" \
  -out    "$CERTS_DIR/ca.crt" \
  -subj   "$SUBJ_CA"

# 2. Certificat serveur signé par CA
echo "[2/3] Génération certificat serveur..."
openssl req -newkey rsa:4096 -nodes \
  -keyout "$CERTS_DIR/server.key" \
  -out    "$CERTS_DIR/server.csr" \
  -subj   "$SUBJ_SRV"

openssl x509 -req -days 365 -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" \
  -CAcreateserial \
  -in  "$CERTS_DIR/server.csr" \
  -out "$CERTS_DIR/server.crt"

# 3. Certificat client signé par CA
echo "[3/3] Génération certificat client..."
openssl req -newkey rsa:4096 -nodes \
  -keyout "$CERTS_DIR/client.key" \
  -out    "$CERTS_DIR/client.csr" \
  -subj   "$SUBJ_CLI"

openssl x509 -req -days 365 -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" \
  -CAcreateserial \
  -in  "$CERTS_DIR/client.csr" \
  -out "$CERTS_DIR/client.crt"

# Nettoyage CSR
rm -f "$CERTS_DIR"/*.csr "$CERTS_DIR"/*.srl

echo ""
echo "✅ Certificats générés dans $CERTS_DIR/"
echo "   ca.crt       — Autorité de certification"
echo "   server.{key,crt} — Certificat serveur"
echo "   client.{key,crt} — Certificat client"
echo ""
echo "Démarrage avec mTLS :"
echo "  CAGOULE_MTLS=1 CAGOULE_API_KEY=<key> cagoule-api"
