#!/usr/bin/env python3
"""
API Routes for authentication
"""
from flask import Flask, jsonify


app = Flask(__name__)


@app.route("/", methods=['GET'])
def index() -> str:
    """Base route"""
    msg = {"message": "Bienvenue"}
    return jsonify(msg)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
