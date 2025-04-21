import mysql.connector
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

# Connexion MySQL
DB_CONFIG = {
    "host": "93.127.192.101",
    "user": "crev3684_KamiDBUSER",
    "password": "g)}JqY)Lhz,_",
    "database": "crev3684_KamiDB"
}

conn = mysql.connector.connect(**DB_CONFIG)
cursor = conn.cursor()
print("Connexion MySQL réussie.")

# Chargement des données
query = "SELECT attack_type, target_system, outcome, attacker_ip, target_ip, user_role, location, Y FROM dataset"
cursor.execute(query)
logs = cursor.fetchall()
columns = ['attack_type', 'target_system', 'outcome', 'attacker_ip', 'target_ip', 'user_role', 'location', 'Y']
df = pd.DataFrame(logs, columns=columns).sample(frac=0.1, random_state=42)
df.drop(columns=['attacker_ip', 'target_ip'], inplace=True)

# Ajout de bruit 2% inversée
noise_idx = df.sample(frac=0.02, random_state=42).index
df.loc[noise_idx, 'Y'] = 1 - df.loc[noise_idx, 'Y']
print(f"{len(noise_idx)} étiquettes bruitées (Y inversé)")

# Encodage et normalisation
df_encoded = pd.get_dummies(df, columns=['attack_type', 'target_system', 'outcome', 'user_role', 'location'], drop_first=True)
X = df_encoded.drop(columns=['Y'])
y = df_encoded['Y']
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)


X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

# Entraînement KNN
model = KNeighborsClassifier(n_neighbors=5, metric='manhattan', weights='distance')
model.fit(X_train, y_train)
y_pred = model.predict(X_test)


print(" Évaluation du KNN :")
print(f"Accuracy  : {accuracy_score(y_test, y_pred):.4f}")
print(f"F1-Score  : {f1_score(y_test, y_pred):.4f}")
print(f"ROC-AUC   : {roc_auc_score(y_test, y_pred):.4f}")

# Matrice de confusion
plt.figure(figsize=(6, 4))
sns.heatmap(confusion_matrix(y_test, y_pred), annot=True, fmt='d', cmap='Blues',
            xticklabels=['Non-Attaque', 'Attaque'], yticklabels=['Non-Attaque', 'Attaque'])
plt.title("Matrice de confusion - KNN (avec bruit)")
plt.xlabel("Prédit")
plt.ylabel("Réel")
plt.show()

# Sauvegarde du modèle
joblib.dump(model, 'knn_model_bruite.pkl')
joblib.dump(scaler, 'scaler_knn.pkl')
joblib.dump(X.columns.tolist(), 'knn_model_features.pkl')
print("\nModèle KNN (avec bruit) sauvegardé.")
