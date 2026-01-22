import time
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify

# -------------------------
# Configuration
# -------------------------

DB_PATH = "snmp.db"          # adapte si besoin (chemin vers ta base)
API_PREFIX = "/api"

app = Flask(__name__)


# -------------------------
# Helpers DB
# -------------------------

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Crée les tables si elles n'existent pas (schéma fourni)."""
    conn = get_db_connection()
    cur = conn.cursor()

    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS snmp_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            oid TEXT NOT NULL,
            value_raw TEXT,
            value_num REAL,
            latency_ms INTEGER
        );

        CREATE TABLE IF NOT EXISTS snmp_traps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            version TEXT,
            community_or_user TEXT,
            enterprise_oid TEXT,
            severity TEXT,
            varbinds TEXT
        );

        CREATE TABLE IF NOT EXISTS snmp_anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            description TEXT,
            severity TEXT,
            type TEXT
        );

        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip_address TEXT NOT NULL UNIQUE,
            location TEXT,
            tags TEXT,
            enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    conn.commit()
    conn.close()


# -------------------------
# (Stub) Fonction SNMP
# -------------------------

def perform_snmp_request(req: dict) -> dict:
    """
    Ici tu brancheras TA vraie logique SNMP.
    Pour l'instant, on simule une réponse pour pouvoir tester l'API + GUI.
    """
    start = time.time()

    # TODO: remplacer par pysnmp / lib SNMP réelle
    # Exemple de pseudo-réponse :
    if req["type"] == "GET":
        simulated_value = f"Simulated GET value for OID {req['oid']}"
        status = "success"
    elif req["type"] == "SET":
        simulated_value = f"Simulated SET value '{req['value']}' on OID {req['oid']}"
        status = "success"
    elif req["type"] == "TRAP":
        simulated_value = "Simulated TRAP sent (nothing to store in metrics)"
        status = "success"
    else:
        simulated_value = "Unknown type"
        status = "error"

    latency_ms = int((time.time() - start) * 1000)

    return {
        "status": status,
        "value": simulated_value,
        "latency_ms": latency_ms,
    }


# -------------------------
# Endpoint: POST /api/snmp
# -------------------------

@app.route(f"{API_PREFIX}/snmp", methods=["POST"])
def send_snmp():
    """
    Attend un JSON:
    {
      "type": "GET" | "SET" | "TRAP",
      "community": "public",
      "target": "192.168.x.x",
      "oid": "1.3.6.1....",
      "value": "..."  // optionnel
    }
    """
    data = request.get_json(silent=True) or {}

    required_fields = ["type", "community", "target", "oid"]
    missing = [f for f in required_fields if not data.get(f)]
    if missing:
        return jsonify({
            "status": "error",
            "error": f"Champs manquants: {', '.join(missing)}"
        }), 400

    snmp_type = data["type"].upper()
    community = data["community"]
    target_ip = data["target"]
    oid = data["oid"]
    value = data.get("value")

    # Appel à la fonction SNMP (stub pour l'instant)
    snmp_result = perform_snmp_request({
        "type": snmp_type,
        "community": community,
        "target": target_ip,
        "oid": oid,
        "value": value,
    })

    # Si c'est un GET ou SET, on stocke dans snmp_metrics
    if snmp_type in ("GET", "SET") and snmp_result["status"] == "success":
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO snmp_metrics (source_ip, oid, value_raw, value_num, latency_ms)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                target_ip,
                oid,
                snmp_result["value"],
                None,  # si tu as une valeur numérique, tu pourras la parser et la mettre ici
                snmp_result["latency_ms"],
            ),
        )
        conn.commit()
        conn.close()

    # Si c'était un TRAP, on pourrait aussi enregistrer dans snmp_traps ici

    response = {
        "status": snmp_result["status"],
        "request": {
            "type": snmp_type,
            "community": community,
            "target": target_ip,
            "oid": oid,
            "value": value,
        },
        "response": {
            "value": snmp_result["value"],
            "latency_ms": snmp_result["latency_ms"],
        }
    }

    return jsonify(response), 200 if snmp_result["status"] == "success" else 500


# -------------------------
# Endpoint: GET /api/history
# -------------------------

@app.route(f"{API_PREFIX}/history", methods=["GET"])
def get_history():
    """
    Renvoie une liste de trames pour la GUI, avec les clés:
    - date
    - type
    - oid
    - cible
    - valeur
    - statut
    Les données viennent de snmp_metrics + snmp_traps.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    # Historique simple basé sur snmp_metrics
    # On pourrait aussi fusionner avec snmp_traps si tu veux voir les TRAP.
    cur.execute(
        """
        SELECT id, ts, source_ip, oid, value_raw, latency_ms
        FROM snmp_metrics
        ORDER BY ts DESC, id DESC
        LIMIT 200
        """
    )

    rows = cur.fetchall()
    conn.close()

    history = []
    for row in rows:
        # ts est une chaîne -> on renvoie telle quelle ou on la formate
        ts = row["ts"]
        # Optionnel : joli format
        # try:
        #     ts = datetime.fromisoformat(row["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        # except Exception:
        #     ts = row["ts"]

        history.append({
            "date": ts,
            "type": "METRIC",               # ou "GET"/"SET" si tu stockes ce détail ailleurs
            "oid": row["oid"],
            "cible": row["source_ip"],
            "valeur": row["value_raw"],
            "statut": f"{row['latency_ms']} ms" if row["latency_ms"] is not None else "OK",
        })

    return jsonify(history), 200


# -------------------------
# Endpoint de test simple
# -------------------------

@app.route(f"{API_PREFIX}/ping", methods=["GET"])
def ping():
    return jsonify({"message": "pong"}), 200


# -------------------------
# Lancement
# -------------------------

if __name__ == "__main__":
    init_db()
    # host="0.0.0.0" pour accepter depuis d'autres machines si besoin
    app.run(host="127.0.0.1", port=5000, debug=True)
