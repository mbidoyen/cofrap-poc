COFRAP - Backend (OpenFaaS Functions)
Trois fonctions serverless Python pour authentification multi-facteurs.

Fonctions
generate-password : génération mot de passe + QR code
generate-2fa : génération secret TOTP + QR code
authenticate : vérification credentials + TOTP + expiration 6 mois

Build & Deploy
faas-cli template store pull python3-http
faas-cli build -f stack.yaml
faas-cli push -f stack.yaml
faas-cli deploy -f stack.yaml

Repos liés
Infra : https://github.com/gmeline/mspr-2-infra
Frontend : https://github.com/mbidoyen/mspr-2-backend
EOF
