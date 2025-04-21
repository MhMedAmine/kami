import mysql.connector
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

# Connexion à la base de données
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "cyberattacks"
}

conn = mysql.connector.connect(**DB_CONFIG)
cursor = conn.cursor()
print("Connexion MySQL réussie.")

# Charger uniquement les logs normaux (Y = 0)
query = """
    SELECT target_system, outcome, attacker_ip, target_ip, user_role, location 
    FROM dataset 
    WHERE Y = 0
"""
cursor.execute(query)
logs = cursor.fetchall()

# Convertir les résultats en DataFrame
columns = ['target_system', 'outcome', 'attacker_ip', 'target_ip', 'user_role', 'location']
df = pd.DataFrame(logs, columns=columns)

# Encodage simple des colonnes catégorielles (si besoin, tu peux améliorer)
df_encoded = pd.get_dummies(df)

# Standardisation
scaler = StandardScaler()
X_scaled = scaler.fit_transform(df_encoded)

# Entraîner le modèle Isolation Forest
model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
model.fit(X_scaled)
import json

# Sauvegarde des noms des features dans un fichier JSON
model_features = list(df_encoded.columns)  # Vous prenez les noms des colonnes après encodage

with open('model_features.json', 'w') as f:
    json.dump(model_features, f)

print("Noms des features sauvegardés dans 'model_features.json'.")


# Sauvegarder le modèle et le scaler
joblib.dump(model, 'isolation_model.pkl')
joblib.dump(scaler, 'isolation_scaler.pkl')

print("Modèle Isolation Forest et scaler sauvegardés avec succès.")
