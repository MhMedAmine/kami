from flask import Flask, request, jsonify
import re
import mysql.connector
from datetime import datetime, timezone
import pandas as pd
import joblib
import requests
import jwt
import smtplib
from email.mime.text import MIMEText
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === Configs ===
DB_CONFIG = {
    "host": "93.127.192.101",
    "user": "crev3684_KamiDBUSER",
    "password": "g)}JqY)Lhz,_",
    "database": "crev3684_KamiDB"
}

JWT_SECRET_KEY = "MySuperUltraSecretKeyJWT2025@Flask#Dotnet!!"
JWT_ALGORITHM = "HS256"
DOTNET_API_BASE = "https://localhost:7108/api/UsersApi"

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "qardouzabir@gmail.com"
SMTP_PASSWORD = "hdpz svtg qnph elbc"

# === Connexion MySQL ===
try:
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    print("Connexion MySQL réussie.")
except mysql.connector.Error as e:
    print(f"Erreur MySQL : {e}")
    exit(1)

# === Modèle IA ===
model = joblib.load('models/knn_model_bruite.pkl')
scaler = joblib.load('models/scaler_knn.pkl')
model_features = joblib.load('models/knn_model_features.pkl')

def get_user_from_jwt_token():
    token = None
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM], options={"verify_aud": False})
            user_id = decoded.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier") \
                      or decoded.get("nameid") or decoded.get("sub")
            role = decoded.get("http://schemas.microsoft.com/ws/2008/06/identity/claims/role") or decoded.get("role")
            if user_id:
                return int(user_id), role
        except jwt.InvalidTokenError as e:
            print("JWT invalide :", e)
    return None, None

def get_user_info(user_id):
    try:
        response = requests.get(f"{DOTNET_API_BASE}/{user_id}", verify=False)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print("Erreur API .NET :", e)
    return {}
def get_admin_email():
    try:
        response = requests.get(f"{DOTNET_API_BASE}/admin", verify=False)
        if response.status_code == 200:
            data = response.json()
            return data.get("email")
        else:
            print("Échec récupération email admin:", response.status_code)
    except Exception as e:
        print("Erreur lors de la récupération de l'email admin:", e)
    return None

def send_email_to_admin(subject, body, admin_email):
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = SMTP_USER
        msg['To'] = admin_email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, admin_email, msg.as_string())
        print("Email envoyé à l’administrateur.")
        print("Admin Email utilisé :", admin_email)
    except Exception as e:
        print("Erreur envoi email :", e)

# === Détection par regex ===
SQL_INJECTION_REGEX = r"(?:'|\"|`|--|#|/\*|\*/|\bUNION\b|\bSELECT\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b|\bDROP\b|\bOR\b|\bAND\b).*?(?:'|\"|`|--|#|/\*)"

ATTACK_PATTERNS = {
    "brute force": [re.escape(p) for p in [
        "login failed", "authentication failure", "invalid password", "multiple failed attempts"
    ]],
    "scan de ports": [re.escape(p) for p in [
        "nmap scan", "port scan", "masscan", "probing ports"
    ]],
    "ddos": [re.escape(p) for p in [
        "high traffic volume", "connection flood", "rate limit exceeded", "service unavailable"
    ]],
    "injection sql": [SQL_INJECTION_REGEX],  # NE PAS échapper celui-là
    "exfiltration": [re.escape(p) for p in [
        "large data transfer", "data export", "unusual download", "unauthorized export"
    ]],
    "accès non autorisé": [re.escape(p) for p in [
        "unauthorized access", "forbidden", "403", "access denied", "admin access attempt"
    ]],
    "xss": [re.escape(p) for p in [
        "<script>", "onerror", "alert(", "document.cookie", "xss test"
    ]],
    "path traversal": [re.escape(p) for p in [
        "../", "..\\", "%2e%2e", "/etc/passwd", "boot.ini", "windows/system32"
    ]],
    "rce": [re.escape(p) for p in [
        "system(", "exec(", "eval(", "bash -i", "wget http", "curl http"
    ]]
}


ATTACK_EXPLANATIONS = {
    "brute force": "Plusieurs échecs de connexion consécutifs.",
    "scan de ports": "Scan de ports détecté, potentiellement par un outil automatisé.",
    "ddos": "Flux de requêtes anormalement élevé, possible attaque par déni de service.",
    "injection sql": "Tentative d'injection SQL détectée dans les paramètres URL.",
    "exfiltration": "Tentative d'exfiltration de données sensibles.",
    "accès non autorisé": "Accès refusé à une ressource sécurisée.",
    "xss": "Tentative d'injection de script malveillant.",
    "path traversal": "Tentative d'accès à des fichiers systèmes par traversée de répertoire.",
    "rce": "Tentative d'exécution de commande distante."
}


def detect_attack_type(message):
    for attack, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, message, re.IGNORECASE):
                return attack
    return "normal"

# === Logger ===
def log_request(request):
    now = datetime.now(timezone.utc)
    date, heure = now.date(), now.time()
    source_ip = request.remote_addr
    method = request.method
    user_agent = request.headers.get('User-Agent', 'Unknown')
    data = request.get_json() if method == 'POST' and request.is_json else request.args
    request_params = " ".join([f"{k}={v}" for k, v in data.items()])
    url = request.base_url
    attack_type = detect_attack_type(url + " " + request_params)
    attack_description = ATTACK_EXPLANATIONS.get(attack_type, "Activité normale.")
    df_input = pd.DataFrame([data])
    df_input_encoded = pd.get_dummies(df_input).reindex(columns=model_features, fill_value=0)
    prediction = model.predict(scaler.transform(df_input_encoded))[0]

    user_id, _ = get_user_from_jwt_token()
    user_info = get_user_info(user_id) if user_id else {}
    send_to = user_info.get("role", "user")
    admin_email = get_admin_email()

    try:
        cursor.execute("""
            INSERT INTO logs (Date, Heure, Source_IP, Message, attack_type, target_system, outcome, attacker_ip, target_ip, user_role, location)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            date, heure, source_ip, f"{method} {url} {request_params}", attack_type,
            data.get('target_system', 'unknown'), data.get('outcome', 'unknown'),
            data.get('attacker_ip', source_ip), data.get('target_ip', '127.0.0.1'),
            send_to, data.get('location', 'unknown')
        ))
        conn.commit()
        log_id = cursor.lastrowid

        if log_id:
            if attack_type != "normal":
                cursor.execute("INSERT INTO attackdetected (type, Description, Log_ID) VALUES (%s, %s, %s)",
                               (attack_type, attack_description, log_id))
                cursor.execute("INSERT INTO alert (Message, Log_ID, User_ID, Send_To, Created_At) VALUES (%s, %s, %s, %s, NOW())",
                               (attack_description, log_id, user_id, send_to))
                if send_to == "user" and admin_email:
                    send_email_to_admin(
                        "Nouvelle alerte envoyée à un utilisateur",
                        f"Alerte détectée et envoyée à l'utilisateur #{user_id}\n\nType: {attack_type}\nDescription: {attack_description}\nIP: {source_ip}\nURL: {url}",
                        admin_email
                    )

            elif prediction == 1:
                cursor.execute("INSERT INTO alert (Message, Log_ID, User_ID, Send_To, Created_At) VALUES (%s, %s, %s, %s, NOW())",
                               ("IA: activité anormale détectée.", log_id, None, "admin"))
        conn.commit()
    except mysql.connector.Error as e:
        print("Erreur MySQL :", e)

    # === Blocage du flux si une attaque est détectée ===
    attack_detected_by_rules = attack_type != "normal"
    attack_detected_by_ia = prediction == 1

    if attack_detected_by_rules or attack_detected_by_ia:
        return jsonify({
            "attack_type": attack_type,
            "prediction_IA": "Attaque" if attack_detected_by_ia else "Normal",
            "status": "blocked",
            "message": "Flux bloqué suite à détection d'activité malveillante."
        }), 403

    # === Si aucune attaque, renvoyer réponse normale ===
    return {
        "attack_type": attack_type,
        "prediction_IA": "Normal",
        "source_ip": source_ip,
        "status": "OK - pas d'attaque"
    }

# === Flask App ===
app = Flask(__name__)

@app.route('/')
def index():
    return "Bienvenue sur l'API de détection !"

@app.route('/inject', methods=['GET', 'POST'])
def inject():
    return log_request(request)

@app.route('/attacks/statistics', methods=['GET'])
def stats():
    cursor.execute("""
        SELECT type, DATE(Date) as day, COUNT(*) FROM attackdetected 
        JOIN logs ON attackdetected.Log_ID = logs.Log_ID
        GROUP BY type, day ORDER BY day DESC
    """)
    return jsonify([{"type": r[0], "date": r[1].isoformat(), "count": r[2]} for r in cursor.fetchall()])
@app.route('/alerts/<int:alert_id>', methods=['DELETE'])
def delete_alert(alert_id):
    try:
        cursor.execute("DELETE FROM alert WHERE Alert_ID = %s", (alert_id,))
        conn.commit()
        return jsonify({"message": "Alerte supprimée avec succès."}), 200
    except mysql.connector.Error as e:
        return jsonify({"error": str(e)}), 500

@app.route('/dashboard/summary')
def dashboard_summary():
    try:
        # Total attaques détectées
        cursor.execute("SELECT COUNT(*) FROM attackdetected")
        total_attacks = cursor.fetchone()[0]

        # Total alertes
        cursor.execute("SELECT COUNT(*) FROM alert")
        total_alerts = cursor.fetchone()[0]

        return jsonify({
            "total_attacks": total_attacks,
            "total_alerts": total_alerts
        })
    except mysql.connector.Error as e:
        return jsonify({"error": str(e)}), 500

@app.route('/alerts', methods=['GET'])
def get_alerts():
    cursor.execute("SELECT Alert_ID, User_ID, Message, Log_ID, Send_To, Created_At FROM Alert ORDER BY Created_At DESC")
    return jsonify([{
        "Alert_Id": r[0], "User_Id": r[1], "Message": r[2], "Log_Id": r[3], "Send_To": r[4],
        "Created_At": r[5].isoformat() if r[5] else None
    } for r in cursor.fetchall()])

if __name__ == '__main__':
    app.run(debug=True)
