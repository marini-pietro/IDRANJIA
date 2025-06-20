"""
API server for the application.
This server handles incoming requests and routes them to the appropriate blueprints.
It also provides a health check endpoint and a shutdown endpoint.
"""

from typing import Union, List, Dict, Any
from os import listdir as os_listdir
from os.path import join as os_path_join
from os.path import dirname as os_path_dirname
from os.path import abspath as os_path_abspath
from importlib import import_module
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager
from flask_marshmallow import Marshmallow
from flasgger import Swagger
import os

from api_blueprints.blueprints_utils import log, is_rate_limited
from config import (
    API_SERVER_HOST,
    API_SERVER_PORT,
    API_SERVER_DEBUG_MODE,
    API_SERVER_NAME_IN_LOG,
    STATUS_CODES,
    API_VERSION,
    URL_PREFIX,
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_QUERY_STRING_NAME,
    JWT_JSON_KEY,
    JWT_REFRESH_JSON_KEY,
    JWT_TOKEN_LOCATION,
    JWT_REFRESH_TOKEN_EXPIRES,
    API_SERVER_RATE_LIMIT,
    API_SERVER_SSL,
    API_SERVER_SSL_CERT,
    API_SERVER_SSL_KEY,
    SQL_PATTERN,
    SQLALCHEMY_DATABASE_URI,
    SQLALCHEMY_TRACK_MODIFICATIONS,
    SWAGGER_CONFIG,
)
from models import db

# Create a Flask app
main_api = Flask(__name__)

# Add OpenAPI specs for auth_server endpoints to the Swagger template
swagger_template = {
    "openapi": "3.0.2",
    "info": {
        "title": "IDRANJIA API",
        "version": API_VERSION,
        "description": "API documentation for IDRANJIA, including authentication endpoints.",
    },
    "paths": {
        # Only include endpoints data from other services here.
        # Do NOT include API server blueprint endpoints here since they are automatically generated.
        "/auth/login": {
            "post": {
                "tags": ["Authentication (auth_server)"],
                "summary": "Login endpoint to authenticate users and generate JWT tokens.",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "email": {
                                        "type": "string",
                                        "example": "user@example.com",
                                    },
                                    "password": {
                                        "type": "string",
                                        "example": "mypassword",
                                    },
                                },
                                "required": ["email", "password"],
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Successful login, returns JWT tokens",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "access_token": {"type": "string"},
                                        "refresh_token": {"type": "string"},
                                    },
                                }
                            }
                        },
                    },
                    "400": {"description": "Bad request (missing or invalid data)"},
                    "401": {"description": "Invalid credentials"},
                },
            }
        },
        "/auth/validate": {
            "post": {
                "tags": ["Authentication (auth_server)"],
                "summary": "Validate endpoint to check the validity of a JWT token.",
                "security": [{"bearerAuth": []}],
                "responses": {
                    "200": {
                        "description": "Token is valid",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "identity": {"type": "string"},
                                        "role": {"type": "string"},
                                    },
                                }
                            }
                        },
                    },
                    "401": {"description": "Invalid or expired token"},
                },
            }
        },
        "/auth/refresh": {
            "post": {
                "tags": ["Authentication (auth_server)"],
                "summary": "Refresh endpoint to issue a new access token using a refresh token.",
                "security": [{"bearerAuth": []}],
                "responses": {
                    "200": {
                        "description": "New access token issued",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "access_token": {"type": "string"},
                                    },
                                }
                            }
                        },
                    },
                    "401": {"description": "Invalid or expired refresh token"},
                },
            }
        },
        "/health": {
            "get": {
                "tags": ["Authentication (auth_server)"],
                "summary": "Health check endpoint to verify the auth server is running.",
                "responses": {
                    "200": {
                        "description": "Server is healthy",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "status": {"type": "string", "example": "ok"},
                                    },
                                }
                            }
                        },
                    }
                },
            }
        },
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
        }
    },
}

# Configure Flasgger (Swagger UI) with the combined template
main_api.config["SWAGGER"] = {
    "title": "IDRANJIA API Documentation",
    "uiversion": 3,
    "openapi": "3.0.2",
}
swagger = Swagger(main_api, template=swagger_template, config=SWAGGER_CONFIG)

# Configure JWT validation settings
main_api.config["JWT_SECRET_KEY"] = (
    JWT_SECRET_KEY  # Same secret key as the auth microservice
)
main_api.config["JWT_ALGORITHM"] = (
    JWT_ALGORITHM  # Same algorithm as the auth microservice
)
main_api.config["JWT_TOKEN_LOCATION"] = JWT_TOKEN_LOCATION  # Where to look for tokens
main_api.config["JWT_QUERY_STRING_NAME"] = (
    JWT_QUERY_STRING_NAME  # Custom query string name
)
main_api.config["JWT_JSON_KEY"] = JWT_JSON_KEY  # Custom JSON key for access tokens
main_api.config["JWT_REFRESH_JSON_KEY"] = (
    JWT_REFRESH_JSON_KEY  # Custom JSON key for refresh tokens
)
main_api.config["JWT_REFRESH_TOKEN_EXPIRES"] = (
    JWT_REFRESH_TOKEN_EXPIRES  # Refresh token valid duration
)
main_api.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
main_api.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = SQLALCHEMY_TRACK_MODIFICATIONS

# Initialize JWTManager for validation only
jwt = JWTManager(main_api)

# Initialize Marshmallow
ma = Marshmallow(main_api)

# Initialize SQLAlchemy
db.init_app(main_api)


def is_input_safe(data: Union[str, List[Any], Dict[Any, Any]]) -> bool:
    """
    Check if the input data (string, list, or dictionary) contains SQL instructions.
    Returns True if safe, False if potentially unsafe.

    :param data: str, list, or dict - The input data to validate.
    :return: bool - True if the input is safe, False otherwise.
    """
    if isinstance(data, str):
        return not bool(SQL_PATTERN.search(data))
    if isinstance(data, list):
        for item in data:
            if isinstance(item, str) and SQL_PATTERN.search(item):
                return False
        return True
    if isinstance(data, dict):
        # Check keys and values in the dictionary for SQL patterns
        for key, value in data.items():
            if isinstance(key, str) and SQL_PATTERN.search(key):
                return False
            if isinstance(value, str) and SQL_PATTERN.search(value):
                return False
        return True
    else:
        return "Input must be a string, list of strings, or dictionary with string keys and values."


@main_api.before_request
def validate_user_data():
    """
    Validate user data for all incoming requests by checking for SQL injection,
    JSON presence for methods that use them and JSON format.
    This function is called before each request to ensure
    that the data is safe and valid.
    This does check for any endpoint specific validation, which should be done in the respective blueprint.
    """
    # Validate JSON body for POST, PUT, PATCH methods
    if request.method in ["POST", "PUT", "PATCH"]:
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
        except ValueError:
            return (jsonify("Invalid JSON format"), STATUS_CODES["bad_request"])

        # Validate JSON keys and values for SQL injection
        for key, value in data.items():
            if not is_input_safe(key):
                return (
                    jsonify(
                        {"error": f"Invalid JSON key: {key} suspected SQL injection"}
                    ),
                    STATUS_CODES["bad_request"],
                )
            if isinstance(value, str) and not is_input_safe(value):
                return (
                    jsonify(
                        {
                            "error": f"Invalid JSON value for key '{key}': suspected SQL injection"
                        }
                    ),
                    STATUS_CODES["bad_request"],
                )

    # Validate path variables (if needed)
    if request.view_args:  # Check if view_args is not None
        for key, value in request.view_args.items():
            if not is_input_safe(value):
                return (
                    jsonify(
                        {
                            "error": f"Invalid path variable: {key} suspected SQL injection"
                        }
                    ),
                    STATUS_CODES["bad_request"],
                )


@main_api.before_request
def enforce_rate_limit():
    """
    Enforce rate limiting for all incoming requests.
    """
    if API_SERVER_RATE_LIMIT:  # Check if rate limiting is enabled
        client_ip = request.remote_addr
        if is_rate_limited(client_ip):
            return (
                jsonify({"error": "Rate limit exceeded"}),
                STATUS_CODES["too_many_requests"],
            )


# Handle unauthorized access (missing token)
@jwt.unauthorized_loader
def custom_unauthorized_response(callback):
    return jsonify({"error": "Missing or invalid token"}), STATUS_CODES["unauthorized"]


# Handle invalid tokens
@jwt.invalid_token_loader
def custom_invalid_token_response(callback):
    log(
        log_type="error",
        message=f"api reached with invalid token, callback: {callback}",
        origin_name=API_SERVER_NAME_IN_LOG,
        origin_host=API_SERVER_HOST,
        message_id="UserAction",
        structured_data=f"[host: {API_SERVER_HOST}, port: {API_SERVER_PORT}]",
    )
    return jsonify({"error": "Invalid token"}), STATUS_CODES["unprocessable_entity"]


# Handle expired tokens
@jwt.expired_token_loader
def custom_expired_token_response(jwt_header, jwt_payload):
    return jsonify({"error": "Token has expired"}), STATUS_CODES["unauthorized"]


# Handle revoked tokens (if applicable)
@jwt.revoked_token_loader
def custom_revoked_token_response(jwt_header, jwt_payload):
    return jsonify({"error": "Token has been revoked"}), STATUS_CODES["unauthorized"]


@main_api.route(f"/api/{API_VERSION}/health", methods=["GET"])
def health_check():
    """
    ---
    tags:
      - API Server (api_server)
    summary: Health Check
    description: Returns the status of the API server.
    operationId: api_health_check
    responses:
      200:
        description: Server is running and healthy.
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
    # Register the blueprints
    blueprints_dir: str = os_path_join(
        os_path_dirname(os_path_abspath(__file__)), "api_blueprints"
    )
    for filename in os_listdir(blueprints_dir):
        if filename.endswith("_bp.py"):  # Look for files ending with '_bp.py'

            # Import the module dynamically
            module_name: str = filename[:-3]  # Remove the .py extension
            module = import_module(f"api_blueprints.{module_name}")

            # Get the Blueprint object (assumes the object has the same name as the file)
            blueprint = getattr(module, module_name)

            main_api.register_blueprint(
                blueprint, url_prefix=URL_PREFIX
            )  # Remove '_bp' for the URL prefix
            print(f"Registered blueprint: {module_name} with prefix {URL_PREFIX}")

    # Initialize the database inside the app context
    with main_api.app_context():
        db.create_all()

    # Start the server
    main_api.run(
        host=API_SERVER_HOST,
        port=API_SERVER_PORT,
        debug=API_SERVER_DEBUG_MODE,
        ssl_context=(
            (API_SERVER_SSL_CERT, API_SERVER_SSL_KEY) if API_SERVER_SSL else None
        ),
    )

    # Log the server start
    log(
        log_type="info",
        message="API server started",
        structured_data=f"[host='{API_SERVER_HOST}' port='{API_SERVER_PORT}']",
    )
