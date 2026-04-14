#!/usr/bin/env bash
# gen_certs.sh — Génération de certificats self-signed pour mTLS cagoule-api
# Usage : bash scripts/gen_certs.sh
# Sortie : certs/ca.crt, certs/server.{key,crt}, certs/client.{key,crt}

set -euo pipefail

# Déterminer les chemins absolus
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="$PROJECT_DIR/certs"

# Créer le dossier certs avec les bonnes permissions
mkdir -p "$CERTS_DIR"
chmod 755 "$CERTS_DIR"

SUBJ_CA="/C=TN/ST=Kairouan/O=QuantOS/CN=CagouleCA"
SUBJ_SRV="/C=TN/ST=Kairouan/O=QuantOS/CN=cagoule-api-server"
SUBJ_CLI="/C=TN/ST=Kairouan/O=QuantOS/CN=cagoule-api-client"

echo "──────────────────────────────────"
echo "  cagoule-api — Génération mTLS"
echo "  AVERTISSEMENT : Certificats académiqufile test.pnges"
echo "  Ne pas utiliser en production."
echo "──────────────────────────────────"
echo "📁 Dossier des certificats: $CERTS_DIR"

# 1. CA auto-signé
echo "[1/3] Génération CA..."
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
  -keyout "$CERTS_DIR/ca.key" \
  -out    "$CERTS_DIR/ca.crt" \
  -subj   "$SUBJ_CA" 2>/dev/null

# 2. Certificat serveur signé par CA
echo "[2/3] Génération certificat serveur..."
openssl req -newkey rsa:4096 -nodes \
  -keyout "$CERTS_DIR/server.key" \
  -out    "$CERTS_DIR/server.csr" \
  -subj   "$SUBJ_SRV" 2>/dev/null

openssl x509 -req -days 365 -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" \
  -CAcreateserial \
  -in  "$CERTS_DIR/server.csr" \
  -out "$CERTS_DIR/server.crt" 2>/dev/null

# 3. Certificat client signé par CA
echo "[3/3] Génération certificat client..."
openssl req -newkey rsa:4096 -nodes \
  -keyout "$CERTS_DIR/client.key" \
  -out    "$CERTS_DIR/client.csr" \
  -subj   "$SUBJ_CLI" 2>/dev/null

openssl x509 -req -days 365 -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" \
  -CAcreateserial \
  -in  "$CERTS_DIR/client.csr" \
  -out "$CERTS_DIR/client.crt" 2>/dev/null

# Nettoyage des fichiers temporaires
rm -f "$CERTS_DIR"/*.csr "$CERTS_DIR"/*.srl

# Permissions sécurisées
chmod 600 "$CERTS_DIR"/*.key
chmod 644 "$CERTS_DIR"/*.crt

echo ""
echo "✅ Certificats générés dans $CERTS_DIR/"
ls -la "$CERTS_DIR/"

echo ""
echo "🚀 Démarrage avec mTLS :"
echo "  export CAGOULE_MTLS=true"
echo "  export CAGOULE_API_KEY=\"\$(openssl rand -hex 32)\""
echo "  export CAGOULE_SSL_KEY=$CERTS_DIR/server.key"
echo "  export CAGOULE_SSL_CERT=$CERTS_DIR/server.crt"
echo "  export CAGOULE_SSL_CA=$CERTS_DIR/ca.crt"
echo ""
echo "📝 Test avec curl (mTLS) :"
echo "  curl --cacert $CERTS_DIR/ca.crt \\"
echo "       --cert $CERTS_DIR/client.crt \\"
echo "       --key $CERTS_DIR/client.key \\"
echo "       https://localhost:8000/v1/health"
