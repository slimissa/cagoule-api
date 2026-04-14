#!/bin/bash
# Script de lancement de cagoule-api

cd "$(dirname "$0")"
source ../venv/bin/activate
export CAGOULE_API_KEY="${CAGOULE_API_KEY:-test-key-123}"
export CAGOULE_HOST="${CAGOULE_HOST:-127.0.0.1}"
export CAGOULE_PORT="${CAGOULE_PORT:-8000}"

echo "🚀 Démarrage de cagoule-api..."
echo "   API Key: ${CAGOULE_API_KEY:0:8}..."
echo "   Host: $CAGOULE_HOST"
echo "   Port: $CAGOULE_PORT"
echo ""

python server.py
