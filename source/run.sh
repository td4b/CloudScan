#!/bin/bash

# Activate virtualenv
source "/opt/venv/bin/activate"

# Generate self signed cert.
openssl req -x509 -nodes -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -subj "/C=US/ST=WhiteLane/L=Cloud/O=Dis/CN=cloudscan.cloud"

gunicorn --certfile=cert.pem --keyfile=key.pem -b 0.0.0.0:8443 --workers=2 app & python main.py
