import os
import base64
from os.path import basename as os_path_basename
from typing import List, Dict, Any, Union
from flask import Blueprint, request, Response
from flask_restful import Api, Resource
from flask_jwt_extended import jwt_required
from requests import post as requests_post
from requests.exceptions import RequestException
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from marshmallow import fields, ValidationError

from config import (
    AUTH_SERVER_HOST,
    AUTH_SERVER_PORT,
    STATUS_CODES,
    LOGIN_AVAILABLE_THROUGH_API,
    AUTH_SERVER_SSL,
)
from api_server import ma

from .blueprints_utils import (
    check_authorization,
    log,
    create_response,
    handle_options_request,
    get_hateos_location_string,
)
from models import db, User  # Import User model for ORM

# Define constants
BP_NAME = os_path_basename(__file__).replace("_bp.py", "")

# Create the blueprint and API
user_bp = Blueprint(BP_NAME, __name__)
api = Api(user_bp)


# Define schemas
class UserSchema(ma.Schema):
    email = fields.Email(required=True)
    comune = fields.String(required=True)
    nome = fields.String(required=True)
    cognome = fields.String(required=True)
    admin = fields.Boolean(required=True)
    password = fields.String(required=True)


user_schema = UserSchema()


def hash_password(password: str) -> str:
    # Generate a random salt
    salt = os.urandom(16)

    # Use PBKDF2 to hash the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    hashed_password = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    # Store the salt and hashed password together
    return f"{base64.urlsafe_b64encode(salt).decode('utf-8')}:{hashed_password.decode('utf-8')}"


class UserResource(Resource):

    ENDPOINT_PATHS = [f"/{BP_NAME}/<string:email>"]

    @jwt_required()
    def get(self, email, identity) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Get user by email
        description: Retrieve user information from the database by email.
        parameters:
          - name: email
            in: path
            required: true
            schema:
              type: string
        responses:
          200:
            description: User found
          404:
            description: User not found
        """

        # Fetch user data from the database
        user = User.query.filter_by(email=email).first()

        # Check if user exists
        if user is None:
            return create_response(
                message={"error": "user not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the retrieval
        log(
            log_type="info",
            message=f"UserResource {identity} retrieved user {email} data",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return user data as JSON response
        return create_response(
            message={
                "email": user.email,
                "comune": user.comune,
                "nome": user.nome,
                "cognome": user.cognome,
                "admin": user.admin,
            },
            status_code=STATUS_CODES["ok"],
        )

    @jwt_required()
    def patch(self, email, identity) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Update user by email
        description: Update user information in the database by email. Allows partial updates.
        parameters:
          - name: email
            in: path
            required: true
            schema:
              type: string
        requestBody:
          required: true
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
        responses:
          200:
            description: User updated
          400:
            description: Invalid input
          404:
            description: User not found
        """
        try:
            # Allow partial updates
            data = user_schema.load(request.get_json(), partial=True)
        except ValidationError as err:
            return create_response(
                message={"error": err.messages},
                status_code=STATUS_CODES["bad_request"],
            )

        # Check if the user exists in the database using ORM
        user = User.query.filter_by(email=email).first()
        if not user:
            return create_response(
                message={"error": "user not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Update fields if provided
        if "password" in data and data["password"]:
            user.password = hash_password(data["password"])
        if "comune" in data and data["comune"]:
            user.comune = data["comune"]
        if "nome" in data and data["nome"]:
            user.nome = data["nome"]
        if "cognome" in data and data["cognome"]:
            user.cognome = data["cognome"]
        if "admin" in data:
            user.admin = data["admin"]
        db.session.commit()

        # Log the update
        log(
            log_type="info",
            message=f"UserResource {identity} updated user {email}",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return a success response
        return create_response(
            message={"success": f"User {email} updated"},
            status_code=STATUS_CODES["ok"],
        )

    @jwt_required()
    def delete(self, email, identity) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Delete user by email
        description: Delete a user from the database by email.
        parameters:
          - name: email
            in: path
            required: true
            schema:
              type: string
        responses:
          200:
            description: User deleted
          404:
            description: User not found
        """

        user = User.query.filter_by(email=email).first()

        if user is None:
            return create_response(
                message={"error": "user not found with provided email"},
                status_code=STATUS_CODES["not_found"],
            )

        # Execute the delete query
        db.session.delete(user)
        db.session.commit()

        # Log the deletion
        log(
            log_type="info",
            message=f"UserResource {email} deleted user {identity}",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return a success response
        return create_response(
            message={"success": f"User {email} deleted"},
            status_code=STATUS_CODES["ok"],
        )

    @jwt_required()
    def options(self) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Get allowed HTTP methods for user resource
        description: Returns the allowed HTTP methods for the user resource endpoint.
        responses:
          200:
            description: Allowed methods returned
        """
        return handle_options_request(resource_class=self)


class UserPostResource(Resource):
    """
    UserResource post resource for creating new users.
    This class handles the following HTTP methods:
    - POST: Create a new user
    - OPTIONS: Get allowed HTTP methods for this endpoint
    """

    ENDPOINT_PATHS = [f"/{BP_NAME}"]

    @jwt_required()
    def post(self, identity) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Create a new user
        description: Create a new user in the database.
        requestBody:
          required: true
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
        responses:
          201:
            description: User created
          400:
            description: Invalid input
          409:
            description: User already exists
        """
        try:
            # Validate and deserialize input
            data = user_schema.load(request.get_json())
        except ValidationError as err:
            return create_response(
                message={"error": err.messages},
                status_code=STATUS_CODES["bad_request"],
            )

        email = data["email"]
        password = data["password"]
        comune = data["comune"]
        nome = data["nome"]
        cognome = data["cognome"]
        admin = data.get("admin", False)  # Default to False if not provided

        # Check if the user already exists in the database using EXISTS keyword
        user_exists: bool = User.query.filter_by(email=email).count() > 0
        if user_exists:
            return create_response(
                message={"error": "user with provided email already exists"},
                status_code=STATUS_CODES["conflict"],
            )

        # Hash the password
        hashed_password = hash_password(password)

        # Insert the new user into the database
        new_user = User(
            email=email,
            password=hashed_password,
            comune=comune,
            nome=nome,
            cognome=cognome,
            admin=admin,
        )
        db.session.add(new_user)
        db.session.commit()

        # Log the creation
        log(
            log_type="info",
            message=f"UserResource {identity} created user {email}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return a success response
        return create_response(
            message={
                "outcome": f"User {email} created",
                "location": get_hateos_location_string(bp_name=BP_NAME, id_=email),
            },
            status_code=STATUS_CODES["created"],
        )

    @jwt_required()
    def options(self) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Get allowed HTTP methods for user resource
        description: Returns the allowed HTTP methods for the user resource endpoint.
        responses:
          200:
            description: Allowed methods returned
        """
        return handle_options_request(resource_class=self)


class UserLoginSchema(ma.Schema):
    email = fields.Email(required=True)
    password = fields.String(required=True)


user_login_schema = UserLoginSchema()


class UserLogin(Resource):
    """
    UserResource login resource for managing user authentication.
    This class handles the following HTTP methods:
    - POST: UserResource login
    - OPTIONS: Get allowed HTTP methods for this endpoint
    """

    ENDPOINT_PATHS = [f"/{BP_NAME}/auth/login"]

    def post(self) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: User login
        description: Authenticate a user and return a JWT token.
        requestBody:
          required: true
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserLogin'
        responses:
          200:
            description: Login successful
          400:
            description: Invalid input
          401:
            description: Invalid credentials
          403:
            description: Login not available through API server
          500:
            description: Authentication service unavailable or internal error
        """

        # Check if login is available through the API server
        if not LOGIN_AVAILABLE_THROUGH_API:
            return create_response(
                message={
                    "error": "login not available through API server, "
                    "contact authentication service directly"
                },
                status_code=STATUS_CODES["forbidden"],
            )

        # Validate and deserialize input using Marshmallow
        try:
            data = user_login_schema.load(request.get_json())
        except ValidationError as err:
            return create_response(
                message={"errors": err.messages},
                status_code=STATUS_CODES["bad_request"],
            )

        email: str = data["email"]
        password: str = data["password"]

        try:
            # Forward login request to the authentication service
            response = requests_post(
                f"{"https" if AUTH_SERVER_SSL else "http"}://{AUTH_SERVER_HOST}:{AUTH_SERVER_PORT}/auth/login",
                json={"email": email, "password": password},
                timeout=5,
            )
        except RequestException as ex:

            # Log the error
            log(
                log_type="error",
                message=f"Authentication service unavailable: {str(ex)}",
                structured_data=f"[endpoint='{request.path}' verb='{request.method}']",
            )

            # Return error response
            return create_response(
                message={"error": "authentication service unavailable"},
                status_code=STATUS_CODES["internal_error"],
            )

        # Handle response from the authentication service
        if (
            response.status_code == STATUS_CODES["ok"]
        ):  # If the login is successful, send the token back to the user

            # Logging login is already handled by auth server

            return create_response(
                message=response.json(), status_code=STATUS_CODES["ok"]
            )

        if response.status_code == STATUS_CODES["unauthorized"]:
            log(
                log_type="warning",
                message=f"Failed login attempt for email: {email}",
                structured_data=f"[endpoint='{request.path}' verb='{request.method}']",
            )
            return create_response(
                message={"error": "Invalid credentials"},
                status_code=STATUS_CODES["unauthorized"],
            )

        elif response.status_code == STATUS_CODES["bad_request"]:
            log(
                log_type="error",
                message=f"Bad request during login for email: {email}",
                structured_data=f"[endpoint='{request.path}' verb='{request.method}']",
            )
            return create_response(
                message={"error": "Bad request"},
                status_code=STATUS_CODES["bad_request"],
            )

        elif response.status_code == STATUS_CODES["internal_error"]:
            log(
                log_type="error",
                message=f"Internal error during login for email: {email}",
                structured_data=f"[endpoint='{request.path}' verb='{request.method}']",
            )
            return create_response(
                message={"error": "Internal error"},
                status_code=STATUS_CODES["internal_error"],
            )

        else:
            log(
                log_type="error",
                message=(
                    f"Unexpected error during login for email: {email} "
                    f"with status code: {response.status_code}"
                ),
                structured_data=f"[endpoint='{request.path}' verb='{request.method}']",
            )
            return create_response(
                message={"error": "Unexpected error during login"},
                status_code=STATUS_CODES["internal_error"],
            )

    def options(self) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Get allowed HTTP methods for user login resource
        description: Returns the allowed HTTP methods for the user login endpoint.
        responses:
          200:
            description: Allowed methods returned
        """
        return handle_options_request(resource_class=self)


# Register the resources with the API
api.add_resource(UserResource, *UserResource.ENDPOINT_PATHS)
api.add_resource(UserPostResource, *UserPostResource.ENDPOINT_PATHS)
api.add_resource(UserLogin, *UserLogin.ENDPOINT_PATHS)
