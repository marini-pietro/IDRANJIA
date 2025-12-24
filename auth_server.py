"""
Authentication server for user login and JWT token generation.
This server provides endpoints for user authentication, token validation, and health checks.
"""

# Library imports
import base64
from binascii import Error as BinasciiError
from typing import Dict, Union, List, Any
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidKey
from flasgger import Swagger
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,
    get_jwt,
)

# Local imports
from api_blueprints.blueprints_utils import log, is_rate_limited
from models import db, User
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
    PBKDF2HMAC_SETTINGS,
    SQL_PATTERN,
    SQLALCHEMY_DATABASE_URI,
    SQLALCHEMY_TRACK_MODIFICATIONS,
)

# Initialize Flask app and SQLAlchemy
auth_api = Flask(__name__)
auth_api.config.update(
    SQLALCHEMY_DATABASE_URI=SQLALCHEMY_DATABASE_URI,
    SQLALCHEMY_TRACK_MODIFICATIONS=SQLALCHEMY_TRACK_MODIFICATIONS,
    JWT_SECRET_KEY=JWT_SECRET_KEY,
    JWT_ACCESS_TOKEN_EXPIRES=JWT_ACCESS_TOKEN_EXPIRES,
    JWT_REFRESH_TOKEN_EXPIRES=JWT_REFRESH_TOKEN_EXPIRES,
    JWT_ALGORITHM=JWT_ALGORITHM,
)
db.init_app(auth_api)
jwt = JWTManager(auth_api)

# Initialize Swagger
swagger = Swagger(auth_api)

# Check JWT secret key length
# encode to utf-8 to get byte length and check if it's at least 32 bytes (256 bits)
if len(JWT_SECRET_KEY.encode("utf-8")) < 32:
    raise ValueError("jwt secret key too short")


def verify_password(stored_password: str, provided_password: str) -> bool:
  """Verify a password against a stored PBKDF2 hash with more specific exception handling."""

  try:
    # Split the stored password into salt and hash components
    salt_b64, hash_b64 = stored_password.split(":") # Expecting "salt:hash" format
  except ValueError:
    # stored_password doesn't have the expected "salt:hash" format
    log(
      log_type="warning",
      message="Stored password format invalid",
      origin_name=AUTH_SERVER_NAME_IN_LOG,
      origin_host=AUTH_SERVER_HOST,
    )
    return False

  try:
    # Decode the base64-encoded salt and hash
    salt = base64.urlsafe_b64decode(salt_b64)
    hash_bytes = base64.urlsafe_b64decode(hash_b64)
  except (BinasciiError, ValueError):
    # base64 decoding failed (malformed salt or hash)
    log(
      log_type="warning",
      message="Base64 decoding failed for stored password components",
      origin_name=AUTH_SERVER_NAME_IN_LOG,
      origin_host=AUTH_SERVER_HOST,
    )
    return False

  try:
    # Set up the PBKDF2 HMAC verifier
    # verifier has to be set up with the same parameters used during hashing
    kdf = PBKDF2HMAC(
      algorithm=PBKDF2HMAC_SETTINGS["algorithm"],
      length=PBKDF2HMAC_SETTINGS["length"],
      salt=salt,
      iterations=PBKDF2HMAC_SETTINGS["iterations"],
    )

    # Verify the provided password
    kdf.verify(provided_password.encode("utf-8"), hash_bytes)

    # If no exception was raised, the password is correct
    return True
  except InvalidKey:
    # password verification failed (wrong password)
    return False
  except Exception as exc:
    # Catch-all for unexpected errors; log for troubleshooting
    log(
      log_type="error",
      message=f"Unexpected error during password verification: {exc}",
      origin_name=AUTH_SERVER_NAME_IN_LOG,
      origin_host=AUTH_SERVER_HOST,
    )
    return False


def is_input_safe(data: Union[str, List[str], Dict[Any, Any]]) -> bool:
    """
    Check if the input data (string, list, or dictionary) contains SQL instructions.
    Returns True if safe, False if potentially unsafe.
    """

    # Check for SQL patterns in strings
    if isinstance(data, str):
        return not SQL_PATTERN.search(data)
    
    # Check for SQL patterns in lists of strings
    if isinstance(data, list):
        return all(
            isinstance(item, str) and not SQL_PATTERN.search(item) for item in data
        )
    
    # Check for SQL patterns in dictionary keys and values
    if isinstance(data, dict):
        return all(
            isinstance(key, str)
            and isinstance(value, str)
            and not SQL_PATTERN.search(value)
            for key, value in data.items()
        )
    
    # If data is of an unexpected type, raise TypeError
    raise TypeError(
        "Input must be a string, list of strings, or dictionary with string keys and values."
    )


@auth_api.before_request
def enforce_rate_limit():
    """Enforce rate limiting for all incoming requests."""

    if AUTH_SERVER_RATE_LIMIT and is_rate_limited(request.remote_addr):
        return (
            jsonify({"error": "Rate limit exceeded"}),
            STATUS_CODES["too_many_requests"],
        )


@auth_api.route("/auth/login", methods=["POST"])
def login():
    """
    Login endpoint to authenticate users and generate JWT tokens.
    ---
    tags:
      - Authentication
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              email:
                type: string
                example: user@example.com
              password:
                type: string
                example: mypassword
    responses:
      200:
        description: Successful login, returns JWT tokens
        content:
          application/json:
            schema:
              type: object
              properties:
                access_token:
                  type: string
                  example: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
                refresh_token:
                  type: string
                  example: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
      400:
        description: Bad request (missing or invalid data)
      401:
        description: Invalid credentials
    """

    # Validate request content type and JSON body
    if not request.is_json or request.json is None:
        return (
            jsonify(
                {
                    "error": "Request body must be valid JSON with Content-Type: application/json"
                }
            ),
            STATUS_CODES["bad_request"],
        )
    
    # Parse and validate JSON body
    try:
        data = request.get_json(silent=False) # silent=False to raise error on invalid JSON
        if not data: # Check for empty JSON object
            return (
                jsonify({"error": "Request body must not be empty"}),
                STATUS_CODES["bad_request"],
            )
    except Exception:
        return jsonify({"error": "Invalid JSON format"}), STATUS_CODES["bad_request"]

    # Validate JSON keys and values for SQL injection
    for key, value in data.items():
        if not is_input_safe(key):
            return (
                jsonify({"error": f"Invalid JSON key: {key} suspected SQL injection"}),
                STATUS_CODES["bad_request"],
            )
        if isinstance(value, str):
            # Separate if statemet for performance reasons
            # (expensive regex will be done only if value is a string)
            if not is_input_safe(value):
                return (
                    jsonify(
                        {
                            "error": f"Invalid JSON value for key '{key}': suspected SQL injection"
                        }
                    ),
                    STATUS_CODES["bad_request"],
                )

    # Extract email and password from JSON body
    email = data.get("email")
    password = data.get("password")
    if not email or not password: # Check for missing fields
        return (
            jsonify({"error": "Missing email or password"}),
            STATUS_CODES["bad_request"],
        )

    user = User.query.filter_by(email=email).first() # Fetch user from database
    if user and verify_password(user.password, password): # If the user exists and password is correct
        identity = user.email # Use email as identity
        additional_claims = {"role": user.ruolo} # Add user role as custom claim
        
        # Create access and refresh tokens
        access_token = create_access_token(
            identity=identity, additional_claims=additional_claims
        )
        refresh_token = create_refresh_token(
            identity=identity, additional_claims=additional_claims
        )

        # Logging the successful login event
        log(
            log_type="info",
            message=f"User {email} logged in",
            origin_name=AUTH_SERVER_NAME_IN_LOG,
            origin_host=AUTH_SERVER_HOST,
            structured_data=f"[endpoint='{request.path}' verb='{request.method}']",
        )

        # Return the tokens
        return (
            jsonify({"access_token": access_token, "refresh_token": refresh_token}),
            STATUS_CODES["ok"],
        )
    else: # Invalid credentials (user not found or wrong password)
       return jsonify({"error": "invalid credentials"}), STATUS_CODES["unauthorized"]


@auth_api.route("/auth/validate", methods=["POST"])
@jwt_required()
def validate_token():
    """
    Validate endpoint to check the validity of a JWT token.
    ---
    tags:
      - Authentication
    security:
      - bearerAuth: []
    responses:
      200:
        description: Token is valid
        content:
          application/json:
            schema:
              type: object
              properties:
                identity:
                  type: string
                  example: user@example.com
                role:
                  type: string
                  example: admin
      401:
        description: Invalid or expired token
    """
    
    # Get identity and custom claims from the JWT
    identity = get_jwt_identity()
    user_role = get_jwt().get("role")
    
    return jsonify({"identity": identity, "role": user_role}), STATUS_CODES["ok"]


@auth_api.route("/auth/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """
    Refresh endpoint to issue a new access token using a refresh token.
    ---
    tags:
      - Authentication
    security:
      - bearerAuth: []
    responses:
      200:
        description: New access token issued
        content:
          application/json:
            schema:
              type: object
              properties:
                access_token:
                  type: string
                  example: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
      401:
        description: Invalid or expired refresh token
    """
    # Get the identity from the refresh token
    identity = get_jwt_identity()
    
    # Preserve custom claims from the refresh token (e.g. role) when issuing a new access token
    user_role = get_jwt().get("role")
    additional_claims = {"role": user_role} if user_role is not None else None
    
	# create_access_token expects additional_claims to be a dict or omitted
    if additional_claims:
        new_access_token = create_access_token(
            identity=identity, additional_claims=additional_claims
        )
    else:
        new_access_token = create_access_token(identity=identity)

    # Logging the token refresh event
    log(
        log_type="info",
        message=f"Access token refreshed for identity {identity}",
        origin_name=AUTH_SERVER_NAME_IN_LOG,
        origin_host=AUTH_SERVER_HOST,
        structured_data=f"[endpoint='{request.path}' verb='{request.method}']",
    )
    
    return jsonify({"access_token": new_access_token}), STATUS_CODES["ok"]


@auth_api.route("/health", methods=["GET"])
def health_check():
    """
    Health check endpoint to verify the server is running.
    ---
    tags:
      - Health
    summary: Health check endpoint
    description: Returns a simple status message to indicate the server is healthy.
    operationId: auth_health_check
    responses:
      200:
        description: Server is healthy
        content:
          application/json:
            schema:
              type: object
              properties:
                status:
                  type: string
                  example: ok
    """
    
    return jsonify({"status": "ok"}), STATUS_CODES["ok"]


if __name__ == "__main__":
    # Log server start event
    log(
        log_type="info",
        message="Authentication server started",
        origin_name=AUTH_SERVER_NAME_IN_LOG,
        origin_host=AUTH_SERVER_HOST,
        message_id="ServerAction",
        structured_data=f"[host='{AUTH_SERVER_HOST}' port='{AUTH_SERVER_PORT}']",
    )
    # Run the Flask authentication server
    auth_api.run(
        host=AUTH_SERVER_HOST,
        port=AUTH_SERVER_PORT,
        debug=AUTH_SERVER_DEBUG_MODE,
        ssl_context=(
            (AUTH_SERVER_SSL_CERT, AUTH_SERVER_SSL_KEY) if AUTH_SERVER_SSL else None
        ),
    )
