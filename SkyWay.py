"""
skyport-vulnerable-demo
Aplicación de demostración con fallas de seguridad INTENCIONALES (versión v0-vulnerable
ya remediada), creada para el ejercicio EX·04/EX·05 (Laboratorio 04 - DevSecOps/SAST),
de la asignatura Fundamentos y Seguridad de la Información,
Escuela Colombiana De Ingeniería Julio Garavito.

Tema: sistema de gestión de vuelos y pasajeros de un aeropuerto ficticio.
"""

import hashlib
import os
import sqlite3
import subprocess

from flask import Flask, request, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "skyport.db")
BOARDING_PASSES_DIR = os.path.join(os.path.dirname(__file__), "boarding_passes")

# CWE-798 (fix): el secreto ya NO está escrito en el código.
# Se lee desde una variable de entorno; si no existe, la app arranca sin ella
# en vez de tener una clave real embebida en el repositorio.
WEATHER_API_KEY = os.environ.get("WEATHER_API_KEY")


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

    # CWE-89 (fix): consulta parametrizada, ya no se concatena el input del usuario.
    conn = get_db()
    cur = conn.execute(
        "SELECT * FROM passengers WHERE email = ?", (email,)
    )
    passenger = cur.fetchone()
    conn.close()

    # CWE-916 (fix): verificación con hash fuerte (Werkzeug/PBKDF2) en vez de MD5.
    if passenger and check_password_hash(passenger["password_hash"], password):
        return jsonify({"status": "ok", "passenger": passenger["email"]})
    return jsonify({"status": "error", "message": "Credenciales inválidas"}), 401


@app.route("/register", methods=["POST"])
def register():
    email = request.form.get("email", "")
    password = request.form.get("password", "")

    # CWE-916 (fix): hashing fuerte con salt (generate_password_hash usa PBKDF2 por defecto).
    password_hash = generate_password_hash(password)

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

    # CWE-78 (fix): ya no se arma un comando de shell con input del usuario
    # (os.popen(f"curl ...")). Se usa la librería requests, que hace la
    # petición HTTP directamente sin pasar por el intérprete de comandos.
    import requests
    try:
        resp = requests.get(
            f"https://wttr.in/{airport_code}",
            params={"format": "3"},
            timeout=5,
        )
        result = resp.text
    except requests.RequestException:
        result = "No se pudo obtener el clima"

    return jsonify({"output": result})


@app.route("/boarding-pass/<path:filename>", methods=["GET"])
def get_boarding_pass(filename):
    # CWE-22 (fix): se resuelve la ruta final y se verifica que siga
    # estando DENTRO de BOARDING_PASSES_DIR antes de servir el archivo,
    # bloqueando cualquier intento de "../" (path traversal).
    requested_path = os.path.realpath(
        os.path.join(BOARDING_PASSES_DIR, filename)
    )
    base_dir = os.path.realpath(BOARDING_PASSES_DIR)

    if not requested_path.startswith(base_dir + os.sep):
        return jsonify({"status": "error", "message": "Ruta no permitida"}), 400

    if not os.path.isfile(requested_path):
        return jsonify({"status": "error", "message": "Archivo no encontrado"}), 404

    return send_file(requested_path)


@app.route("/flights", methods=["GET"])
def list_flights():
    conn = get_db()
    flights = conn.execute("SELECT * FROM flights").fetchall()
    conn.close()
    return jsonify([dict(f) for f in flights])


if __name__ == "__main__":
    init_db()
    # CWE-668 (fix): ya no se ata por defecto a todas las interfaces (0.0.0.0).
    # Por defecto solo escucha en localhost; si un despliegue real necesita
    # exponerse en la red (contenedor, VM), se define explícitamente vía HOST.
    host = os.environ.get("HOST", "127.0.0.1")
    # CWE-489 (fix): debug=False en cualquier despliegue: debug=True expone el
    # debugger interactivo de Werkzeug (ejecución remota de código).
    app.run(host=host, port=5000, debug=False)