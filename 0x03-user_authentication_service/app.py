#!/usr/bin/env python3
"""
API Routes for authentication
"""
from auth import Auth
from flask import abort, Flask, jsonify, request


app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=['GET'])
def index() -> str:
    """Base route"""
    msg = {"message": "Bienvenue"}
    return jsonify(msg)


@app.route('/user', methods=['POST'])
def register_user() -> str:
    """Registers a new user"""
    try:
        email = request.form['email']
        password = request.form['password']
    except KeyError:
        abort(400)

    try:
        user = Auth.register_user(email, password)
    except ValueError:
        msg = {"message": "email already registered"}
        return jsonify(msg), 400

    msg = {"email": email, "message": "user created"}
    return jsonify(msg)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
