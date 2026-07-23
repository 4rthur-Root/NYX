FROM python:3.13-slim 

# Définit le répertoire de travail dans le conteneur
WORKDIR /nyx

# Copier les fichiers de dépendances d'abord (meilleure mise en cache)
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copie le reste du code
COPY app.py .

# Le port exposé par l'application
EXPOSE 5000

# Commande pour lancer l'appli
CMD ["python", "app.py"]