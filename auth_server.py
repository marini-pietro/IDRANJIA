"""
Authentication server for user login and JWT token generation.
This server provides endpoints for user authentication, token validation, and health checks.
"""

import base64
from typing import Dict, Union, List, Any
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,
    get_jwt,
)
from api_blueprints.blueprints_utils import (
    log,
    fetchone_query,
    is_rate_limited,
)
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
    AUTH_SERVER_RATE_LIMIT,
    AUTH_SERVER_SSL,
    AUTH_SERVER_SSL_CERT,
    AUTH_SERVER_SSL_KEY,
    SQL_PATTERN,
)

# Initialize Flask app
auth_api = Flask(__name__)

# Check JWT secret key length
PASSWORD_NUM_BITS = len(JWT_SECRET_KEY.encode("utf-8")) * 8
if PASSWORD_NUM_BITS < 256:
    raise RuntimeWarning("jwt secret key too short")

# Configure JWT
auth_api.config["JWT_SECRET_KEY"] = (
    JWT_SECRET_KEY  # Use a secure key (ideally at least 256 bits)
)
auth_api.config["JWT_ACCESS_TOKEN_EXPIRES"] = JWT_ACCESS_TOKEN_EXPIRES
auth_api.config["JWT_REFRESH_TOKEN_EXPIRES"] = JWT_REFRESH_TOKEN_EXPIRES
auth_api.config["JWT_ALGORITHM"] = JWT_ALGORITHM

jwt = JWTManager(auth_api)


def verify_password(stored_password: str, provided_password: str) -> bool:
    # Split the stored password into salt and hash
    salt, hashed_password = stored_password.split(":")
    salt = base64.urlsafe_b64decode(salt)

    # Recreate the KDF with the same salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )

    # Verify the provided password
    try:
        kdf.verify(
            provided_password.encode("utf-8"), base64.urlsafe_b64decode(hashed_password)
        )
        return True
    except Exception:
        return False


def is_input_safe(data: Union[str, List[str], Dict[Any, Any]]) -> bool:
    """
    Check if the input data (string, list, or dictionary) contains SQL instructions.
    Returns True if safe, False if potentially unsafe.

    :param data: str, list, or dict - The input data to validate.
    :return: bool - True if the input is safe, False otherwise.
    """
    if isinstance(data, str):
        return not bool(SQL_PATTERN.search(data))
    if isinstance(data, list):
        return all(
            isinstance(item, str) and not bool(SQL_PATTERN.search(item))
            for item in data
        )
    if isinstance(data, dict):
        return all(
            isinstance(key, str)
            and isinstance(value, str)
            and not bool(SQL_PATTERN.search(value))
            for key, value in data.items()
        )
    else:
        raise TypeError(
            "Input must be a string, list of strings, or dictionary with string keys and values."
        )


@auth_api.before_request
def enforce_rate_limit():
    """
    Enforce rate limiting for all incoming requests.
    """
    if AUTH_SERVER_RATE_LIMIT:  # Check if rate limiting is enabled
        client_ip = request.remote_addr
        if is_rate_limited(client_ip):
            return (
                jsonify({"error": "Rate limit exceeded"}),
                STATUS_CODES["too_many_requests"],
            )


@auth_api.route("/auth/login", methods=["POST"])
def login():
    """
    Login endpoint to authenticate users and generate JWT tokens.
    """

    if not request.is_json or request.json is None:
        return (
            jsonify(
                "Request body must be valid JSON with Content-Type: application/json"
            ),
            STATUS_CODES["bad_request"],
        )
    try:
        data = request.get_json(silent=False)
        if data == {}:
            return (
                jsonify("Request body must not be empty"),
                STATUS_CODES["bad_request"],
            )
    except (ValueError, Exception):
        return (jsonify("Invalid JSON format"), STATUS_CODES["bad_request"])

    # Validate JSON keys and values for SQL injection
    for key, value in data.items():
        if not is_input_safe(key):
            return (
                jsonify({"error": f"Invalid JSON key: {key} suspected SQL injection"}),
                STATUS_CODES["bad_request"],
            )
        if isinstance(value, str):
            # Separate if statements for optimization
            # (heavy regex search will be done only if value is a string)
            if not is_input_safe(value):
                return (
                    jsonify(
                        {
                            "error": f"Invalid JSON value for key '{key}': suspected SQL injection"
                        }
                    ),
                    STATUS_CODES["bad_request"],
                )

    # Gather parameters
    data = request.get_json()
    email: str = data.get("email")
    password: str = data.get("password")

    # Query the database to retrieve the user's hashed password and role
    user: Dict[str, Any] = fetchone_query(
        "SELECT email_utente, password, ruolo "
        "FROM utenti "
        "WHERE email_utente = %s",
        (email,),
    )

    if user:
        # Verify the provided password against the stored hashed password
        if verify_password(user["password"], password):
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
                structured_data=f"[endpoint='{request.path}' verb='{request.method}']",
            )

            # Return both tokens
            return (
                jsonify({"access_token": access_token, "refresh_token": refresh_token}),
                STATUS_CODES["ok"],
            )

    # Handle invalid credentials
    return jsonify({"error": "invalid credentials"}), STATUS_CODES["unauthorized"]


@auth_api.route("/auth/validate", methods=["POST"])
@jwt_required()  # Require a valid access token
def validate_token():
    """
    Validate endpoint to check the validity of a JWT token.
    """
    # Get the identity from the access token
    identity = get_jwt_identity()
    user_role = get_jwt().get("role")

    # Return the identity and a success message
    return (
        jsonify({"identity": identity, "role": user_role}),
        STATUS_CODES["ok"],
    )


@auth_api.route("/auth/refresh", methods=["POST"])
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


@auth_api.route("/health", methods=["GET"])
def health_check():
    """
    Health check endpoint to verify the server is running.
    """
    return jsonify({"status": "ok"}), STATUS_CODES["ok"]


if __name__ == "__main__":
    auth_api.run(
        host=AUTH_SERVER_HOST,
        port=AUTH_SERVER_PORT,
        debug=AUTH_SERVER_DEBUG_MODE,
        ssl_context=(
            (AUTH_SERVER_SSL_CERT, AUTH_SERVER_SSL_KEY) if AUTH_SERVER_SSL else None
        ),
    )
    log(
        log_type="info",
        message="Authentication server started",
        origin_name=AUTH_SERVER_NAME_IN_LOG,
        origin_host=AUTH_SERVER_HOST,
        message_id="ServerAction",
        structured_data=f"[host='{AUTH_SERVER_HOST}' port='{AUTH_SERVER_PORT}']",
    )
