#!/bin/bash

# Ferma lo script se si verifica un errore
set -e

echo "=== [1/2] Generazione dei certificati SSL sull'host ==="
# Genera i certificati sovrascrivendo quelli vecchi se esistono
openssl req -x509 -newkey rsa:2048 \
    -keyout server.key -out server.crt -days 365 -nodes \
    -subj "/C=IT/ST=Italy/L=Milan/O=University/CN=localhost" 2>/dev/null

echo "--> Certificati (server.key, server.crt) generati con successo."
echo ""

echo "=== [2/2] Costruzione dell'immagine Docker ==="
docker buildx build -t server_lucky13 .

echo ""
echo "--> Automazione completata! Immagine 'server_lucky13' pronta."
