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


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)