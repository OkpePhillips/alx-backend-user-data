#!/usr/bin/env python3
"""
App module which serves as entry point to the application.
"""
from auth import Auth
from flask import Flask, jsonify, request, abort, make_response, redirect


app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=["GET"])
def index():
    """Route handler for the root endpoint."""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def users():
    """Endpoint to register a user."""
    try:
        email = request.form.get("email")
        password = request.form.get("password")

        user = AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"}), 200
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"])
def login():
    """Endpoint to log in a user."""
    email = request.form.get("email")
    password = request.form.get("password")

    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        response = make_response(jsonify({"email": email,
                                 "message": "logged in"}), 200)
        response.set_cookie("session_id", session_id)
        return response
    else:
        abort(401, "Invalid email or password.")


@app.route("/sessions", methods=["DELETE"])
def logout():
    """Endpoint to log out a user."""
    session_id = request.cookies.get("session_id")

    user = AUTH.get_user_from_session_id(session_id)
    if user:
        AUTH.destroy_session(user.id)
        return redirect("/")
    else:
        abort(403, "Invalid session ID.")


@app.route("/profile", methods=["GET"])
def profile():
    """
    Endpoint to retrieve user profile.
    """
    session_id = request.cookies.get("session_id")

    user = AUTH.get_user_from_session_id(session_id)
    if user:
        return jsonify({"email": user.email}), 200
    else:
        abort(403, "Invalid session ID.")


@app.route("/reset_password", methods=["POST"])
def get_reset_password_token():
    """Endpoint to generate a reset password token."""
    email = request.form.get("email")

    if not email:
        abort(400, "Email not provided.")

    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email,
                        "reset_token": reset_token}), 200
    except ValueError as e:
        abort(403, str(e))


@app.route("/reset_password", methods=["PUT"])
def update_password():
    """
    Endpoint to update the password.
    """
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")

    if not email or not reset_token or not new_password:
        abort(400, "Missing required fields.")

    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email,
                        "message": "Password updated"}), 200
    except ValueError as e:
        abort(403, str(e))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
