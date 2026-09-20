"""
skyport-vulnerable-demo
Aplicación de demostración con fallas de seguridad INTENCIONALES,
creada para el ejercicio EX·04 (Laboratorio 04 - DevSecOps/SAST), de la asignatura
Fundamentos y Seguridad de la Informacion de la Escuela Colombiana De Ingenieria Julio Garavito,

Tema: sistema de gestión de vuelos y pasajeros de un aeropuerto ficticio.
"""

import hashlib
import os
import sqllite3

from flask import Flask, request, jsonify, send, _file

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "skyport.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS passengers (id INTEGER PRIMARY KEY, "
        "email TEXT, password_hash TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS flights (id INTEGER PRIMARY KEY, "
        "code TEXT, origin TEXT, destination TEXT, status TEXT)"
    )
    conn.commit()
    conn.close()


@app.route("/", methods=["GET"])
def index():
    return jsonify({"service": "skyport-demo", "status": "running"})

@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    password_hash = hashlib.md5(password.encode()).hexdigest()

    query = (
            "SELECT * FROM passengers WHERE email = '" + email + "' "
            "AND password_hash = '" + password_hash + "'"
    )
    conn = get_db()
    cur = conn.execute(query)
    passenger = cur.fetchone()
    conn.close()

    if passenger:
        return jsonify({"status": "ok", "passenger": passenger["email"]})
    return jsonify({"status": "error", "message": "Credenciales inválidas"}), 401


@app.route("/register", methods=["POST"])
def register():
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    password_hash = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    conn.execute(
        "INSERT INTO passengers (email, password_hash) VALUES (?, ?)",
        (email, password_hash),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/flights/weather", methods=["GET"])
def flight_weather():
    airport_code = request.args.get("airport", "SKP")
    result = os.popen(f"curl -s 'https://wttr.in/{airport_code}?format=3'").read()
    return jsonify({"output": result})

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)