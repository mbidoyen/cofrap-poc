#!/bin/bash
# Script de démarrage COFRAP
# Usage : ./start.sh [k3s|minikube]

set -e

echo "======================================"
echo "  COFRAP — Démarrage de l'infrastructure"
echo "======================================"

# Détecter l'environnement si pas précisé
ENV=${1:-auto}

if [ "$ENV" = "auto" ]; then
  if command -v k3s &> /dev/null; then
    ENV="k3s"
  elif command -v minikube &> /dev/null; then
    ENV="minikube"
  else
    echo "Erreur : ni K3s ni Minikube détecté."
    echo "Usage : ./start.sh [k3s|minikube]"
    exit 1
  fi
fi

echo "Environnement détecté : $ENV"

# Minikube : démarrer le cluster si nécessaire
if [ "$ENV" = "minikube" ]; then
  echo ""
  echo ">>> Démarrage de Minikube..."
  minikube status | grep -q "Running" || minikube start --cpus=2 --memory=4096
  echo ">>> Minikube actif."
fi

# Vérifier que kubectl fonctionne
echo ""
echo ">>> Vérification du cluster..."
kubectl get nodes
echo ""

# Installer Helm si absent
if ! command -v helm &> /dev/null; then
  echo ">>> Installation de Helm..."
  curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

# Installer OpenFaaS
echo ">>> Déploiement d'OpenFaaS..."
kubectl apply -f https://raw.githubusercontent.com/openfaas/faas-netes/master/namespaces.yml
helm repo add openfaas https://openfaas.github.io/faas-netes/ 2>/dev/null || true
helm repo update
helm upgrade openfaas --install openfaas/openfaas \
  --namespace openfaas \
  --set functionNamespace=openfaas-fn \
  --set generateBasicAuth=true

echo ">>> Attente que OpenFaaS soit prêt..."
kubectl rollout status deployment/gateway -n openfaas --timeout=120s

# Déployer PostgreSQL
echo ""
echo ">>> Déploiement de PostgreSQL..."
kubectl apply -f ../mspr-2-infra/k8s/postgres/postgres.yaml
echo ">>> Attente que PostgreSQL soit prêt..."
kubectl rollout status statefulset/postgres -n data --timeout=120s

# Créer la table
echo ""
echo ">>> Création de la table users..."
sleep 5
kubectl exec -i -n data postgres-0 -- psql -U cofrap_app -d cofrap << 'SQL'
CREATE TABLE IF NOT EXISTS users (
    id        SERIAL PRIMARY KEY,
    username  VARCHAR(64)  UNIQUE NOT NULL,
    password  TEXT         NOT NULL,
    mfa       TEXT         NOT NULL,
    gendate   BIGINT       NOT NULL,
    expired   SMALLINT     DEFAULT 0
);
SQL

# Port-forward gateway
echo ""
echo ">>> Lancement du port-forward gateway..."
kubectl port-forward -n openfaas svc/gateway 8888:8080 \
  --address 0.0.0.0 > /tmp/port-forward.log 2>&1 &
sleep 3

# Récupérer le mot de passe admin et login
echo ""
echo ">>> Connexion à OpenFaaS..."
PASSWORD=$(kubectl -n openfaas get secret basic-auth \
  -o jsonpath="{.data.basic-auth-password}" | base64 --decode)
echo -n $PASSWORD | faas-cli login --username admin --password-stdin --gateway http://127.0.0.1:8888

# Créer les secrets OpenFaaS
echo ""
echo ">>> Création des secrets OpenFaaS..."
echo "ATTENTION : vous devez fournir vos propres valeurs."
echo ""

read -p "Mot de passe PostgreSQL [ChangeMe_S3cret!] : " DB_PASSWORD
DB_PASSWORD=${DB_PASSWORD:-ChangeMe_S3cret!}

# Générer une clé Fernet
FERNET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
echo "Clé Fernet générée : $FERNET_KEY"
echo "IMPORTANT : notez cette clé, elle ne sera plus affichée."
echo ""

# Créer les secrets (supprime d'abord si existants)
for secret in db-host db-name db-user db-password fernet-key; do
  faas-cli secret remove $secret 2>/dev/null || true
done

echo -n "postgres.data.svc.cluster.local" | faas-cli secret create db-host
echo -n "cofrap" | faas-cli secret create db-name
echo -n "cofrap_app" | faas-cli secret create db-user
echo -n "$DB_PASSWORD" | faas-cli secret create db-password
echo -n "$FERNET_KEY" | faas-cli secret create fernet-key

# Installer faas-cli si absent
if ! command -v faas-cli &> /dev/null; then
  echo ">>> Installation de faas-cli..."
  curl -sSL https://cli.openfaas.com | sudo sh
fi

echo ""
echo "======================================"
echo "  Infrastructure prête !"
echo "======================================"
echo ""
echo "Prochaines étapes :"
echo "  1. Aller dans functions/"
echo "  2. faas-cli build -f stack.yaml"
echo "  3. faas-cli push -f stack.yaml"
echo "  4. faas-cli deploy -f stack.yaml"
echo ""
echo "Gateway accessible sur : http://127.0.0.1:8888"
echo "UI OpenFaaS : http://127.0.0.1:8888/ui/"
echo ""
