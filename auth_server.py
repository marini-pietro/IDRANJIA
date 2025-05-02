"""
Authentication server for user login and JWT token generation.
This server provides endpoints for user authentication, token validation, and health checks.
"""

from typing import Dict, Any, Union
from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,
)
from api_blueprints.blueprints_utils import log, fetchone_query, has_valid_json
from config import (
    AUTH_SERVER_HOST,
    AUTH_SERVER_PORT,
    AUTH_SERVER_NAME_IN_LOG,
    AUTH_SERVER_DEBUG_MODE,
    JWT_ACCESS_TOKEN_EXPIRES,
    JWT_SECRET_KEY,
    STATUS_CODES,
    JWT_REFRESH_TOKEN_EXPIRES,
    JWT_ALGORITHM,
)

# Initialize Flask app
app = Flask(__name__)

# Check JWT secret key length
PASSWORD_NUM_BITS = len(JWT_SECRET_KEY.encode("utf-8")) * 8
if PASSWORD_NUM_BITS < 256:
    raise RuntimeWarning("jwt secret key too short")

# Configure JWT
app.config["JWT_SECRET_KEY"] = (
    JWT_SECRET_KEY  # Use a secure key (ideally at least 256 bits)
)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = JWT_ACCESS_TOKEN_EXPIRES
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = JWT_REFRESH_TOKEN_EXPIRES
app.config["JWT_ALGORITHM"] = JWT_ALGORITHM

jwt = JWTManager(app)


@app.route("/auth/login", methods=["POST"])
def login():
    """
    Login endpoint to authenticate users and generate JWT tokens.
    """
    # Validate request
    data: Union[str, Dict[str, Any]] = has_valid_json(request)
    if isinstance(data, str):
        return jsonify({"error": data}), STATUS_CODES["bad_request"]

    email: str = data.get("email")
    password: str = data.get("password")

    # Query the database to validate the user's credentials
    user: Dict[str, Any] = fetchone_query(
        "SELECT email_utente, password, ruolo "
        "FROM utenti "
        "WHERE email_utente = %s AND password = %s",
        (email, password),
    )

    if user:
        # Use a string for the identity (sub claim)
        identity = user["email_utente"]  # Use the email as the identity

        # Add additional claims (e.g., ruolo) as custom claims
        additional_claims = {"role": user["ruolo"]}

        # Generate the access token
        access_token: str = create_access_token(
            identity=identity, additional_claims=additional_claims
        )

        # Generate the refresh token
        refresh_token: str = create_refresh_token(
            identity=identity, additional_claims=additional_claims
        )

        # Log the login operation
        log(
            log_type="info",
            message=f"User {email} logged in",
            origin_name=AUTH_SERVER_NAME_IN_LOG,
            origin_host=AUTH_SERVER_HOST,
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path}' verb='POST']",
        )

        # Return both tokens
        return (
            jsonify({"access_token": access_token, "refresh_token": refresh_token}),
            STATUS_CODES["ok"],
        )

    # Handle invalid credentials
    return jsonify({"error": "Invalid credentials"}), STATUS_CODES["unauthorized"]


@app.route("/auth/refresh", methods=["POST"])
@jwt_required(refresh=True)  # Require a valid refresh token
def refresh():
    """
    Refresh endpoint to issue a new access token using a refresh token.
    """
    # Get the identity from the refresh token
    identity = get_jwt_identity()

    # Generate a new access token
    new_access_token = create_access_token(identity=identity)

    # Return the new access token
    return jsonify({"access_token": new_access_token}), STATUS_CODES["ok"]


@app.route("/health", methods=["GET"])
def health_check():
    """
    Health check endpoint to verify the server is running.
    """
    return jsonify({"status": "ok"}), STATUS_CODES["ok"]


if __name__ == "__main__":
    app.run(host=AUTH_SERVER_HOST, port=AUTH_SERVER_PORT, debug=AUTH_SERVER_DEBUG_MODE)
