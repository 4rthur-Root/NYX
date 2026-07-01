# 1. Prérequis
sudo apt install -y ca-certificates curl

# 2. Ajouter la clé GPG officielle de Docker
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# 3. Ajouter le dépôt Docker
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 4. Installer Docker et Compose
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 5. Ajouter l'utilisateur au groupe docker (pour éviter sudo à chaque fois)
sudo usermod -aG docker $USER

# 6. Vérifier
docker --version
docker compose version

# 7. Activer et démarrer Docker
sudo systemctl enable docker
sudo systemctl start docker