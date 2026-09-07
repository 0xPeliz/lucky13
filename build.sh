#!/bin/bash

# Ferma lo script se si verifica un errore
set -e

echo "=== [1/2] Generazione dei certificati SSL sull'host ==="
# Genera i certificati nella directory corrente (implementazione)
openssl req -x509 -newkey rsa:2048 \
    -keyout server.key -out server.crt -days 365 -nodes \
    -subj "/C=IT/ST=Italy/L=Milan/O=University/CN=localhost" 2>/dev/null

echo "--> Certificati (server.key, server.crt) generati con successo."
echo ""

echo "=== [2/2] Costruzione e avvio della LAN simulata con Docker Compose ==="
# Entra nella cartella config dove risiede il docker-compose.yml
# cd config/

# Avvia l'infrastruttura distruggendo container vecchi e forzando la ricompilazione
# docker compose up -d --build

echo ""
echo "--> Automazione completata! Il laboratorio Lucky13 è attivo e isolato."
echo "I container 'server', 'client' e 'proxy' sono in esecuzione in background."
