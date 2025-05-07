from os.path import basename as os_path_basename
from flask import Blueprint, request, Response
from flask_restful import Api, Resource
from requests import post as requests_post
from requests.exceptions import RequestException
from flask_jwt_extended import get_jwt_identity, jwt_required
from typing import Dict, Union, Any
from blueprints_utils import (
    check_authorization,
    fetchone_query,
    fetchall_query,
    execute_query,
    log,
    create_response,
    build_update_query_from_filters,
    handle_options_request,
)
from config import (
    API_SERVER_HOST,
    API_SERVER_PORT,
    API_SERVER_NAME_IN_LOG,
    STATUS_CODES,
    AUTH_SERVER_HOST,
    AUTH_SERVER_PORT,
    LOGIN_AVAILABLE_THROUGH_API,
)

# Define constants
BP_NAME = os_path_basename(__file__).replace("_bp.py", "")

# Create the blueprint and API
user_bp = Blueprint(BP_NAME, __name__)
api = Api(user_bp)


class User(Resource):

    ENDPOINT_PATHS = [f"/{BP_NAME}", f"/{BP_NAME}/<string:email>"]

    @jwt_required()
    def get(self, email) -> Response:
        """
        Get user information from the database by its email.
        The email is passed as a path variable.
        """

        # Fetch user data from the database
        user = fetchone_query(
            query="SELECT * FROM utenti WHERE email = %s",
            params=(email,),
        )

        # Check if user exists
        if user is None:
            return create_response(
                message={"error": "user not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the retrieval
        log(
            message=f"User {get_jwt_identity} retrieved user {email} data",
            status_code=STATUS_CODES["OK"],
            server_name=API_SERVER_NAME_IN_LOG,
            server_host=API_SERVER_HOST,
            server_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{request.path}' verb='{request.method}']",
        )

        # Return user data as JSON response
        return create_response(
            message=user,
            status_code=STATUS_CODES["OK"],
        )

    @jwt_required()
    def post(self) -> Response:
        """
        Create a new user in the database.
        The request body must be a JSON object with application/json content type.
        """

        # Gather parameters
        data = request.get_json()
        email: str = data.get("email")
        password: str = data.get("password")
        comune: str = data.get("comune")

        # Validate parameters
        if email is None or password is None or comune is None:
            return create_response(
                message={"error": "missing email, password or comune"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Check if the user already exists in the database
        existing_user = fetchone_query(
            query="SELECT * FROM utenti WHERE email = %s",
            params=(email,),
        )
        if existing_user is not None:
            return create_response(
                message={"error": "user with provided email already exists"},
                status_code=STATUS_CODES["conflict"],
            )

        # Insert the new user into the database
        execute_query(
            query="INSERT INTO utenti (email, password, comune) VALUES (%s, %s, %s)",
            params=(email, password, comune),
        )

        # Log the creation
        log(
            message=f"User {get_jwt_identity} created user {email}",
            status_code=STATUS_CODES["created"],
            server_name=API_SERVER_NAME_IN_LOG,
            server_host=API_SERVER_HOST,
            server_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{request.path}' verb='{request.method}']",
        )

        # Return a success response
        return create_response(
            message={"success": f"User {email} created"},
            status_code=STATUS_CODES["created"],
        )

    @jwt_required()
    def patch(self) -> Response:
        """
        Update user information in the database.
        The request body must be a JSON object with application/json content type.
        """

        # Gather parameters
        data = request.get_json()
        email: str = data.get("email")
        password: str = data.get("password")
        comune: str = data.get("comune")

        # Validate parameters
        if email is None or (password is None and comune is None):
            return create_response(
                message={"error": "missing email, password or comune"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Check if the user exists in the database
        user = fetchone_query(
            query="SELECT * FROM utenti WHERE email = %s",
            params=(email,),
        )
        if user is None:
            return create_response(
                message={"error": "user not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Build the update query based on provided fields
        update_query, params = build_update_query_from_filters(
            table_name="utenti",
            data=data,
            pk_column="email",
            pk_value=email,
        )

        # Execute the update query
        execute_query(query=update_query, params=params)

        # Log the update
        log(
            message=f"User {get_jwt_identity} updated user {email}",
            status_code=STATUS_CODES["OK"],
            server_name=API_SERVER_NAME_IN_LOG,
            server_host=API_SERVER_HOST,
            server_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{request.path}' verb='{request.method}']",
        )

        # Return a success response
        return create_response(
            message={"success": f"User {email} updated"},
            status_code=STATUS_CODES["OK"],
        )

    @jwt_required()
    def delete(self, email) -> Response:
        """
        Delete a user from the database by its email.
        """

        # Execute the delete query
        _, rows_affected = execute_query(
            query="DELETE FROM utenti WHERE email = %s",
            params=(email,),
        )

        if rows_affected == 0:
            return create_response(
                message={"error": "user not found with provided email"},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the deletion
        log(
            message=f"User {email} deleted",
            status_code=STATUS_CODES["OK"],
            server_name=API_SERVER_NAME_IN_LOG,
            server_host=API_SERVER_HOST,
            server_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{request.path}' verb='{request.method}']",
        )

        # Return a success response
        return create_response(
            message={"success": f"User {email} deleted"},
            status_code=STATUS_CODES["OK"],
        )

    @jwt_required()
    def options(self) -> Response:
        """
        Handle OPTIONS request for CORS preflight.
        This method returns the allowed HTTP methods for this endpoint.
        """
        return handle_options_request(resource_class=self)


class UserLogin(Resource):
    """
    User login resource for managing user authentication.
    This class handles the following HTTP methods:
    - POST: User login
    - OPTIONS: Get allowed HTTP methods for this endpoint
    """

    ENDPOINT_PATHS = [f"/{BP_NAME}/auth/login"]

    def post(self) -> Response:
        """
        User login endpoint.
        The request body must be a JSON object with application/json content type.
        """

        # Check if login is available through the API server
        if not LOGIN_AVAILABLE_THROUGH_API:
            return create_response(
                message={
                    "error": "login not available through API server, contact authentication service directly"
                },
                status_code=STATUS_CODES["forbidden"],
            )

        # Gather parameters
        data = request.get_json()
        email: str = data.get("email")
        password: str = data.get("password")

        # Validate parameters
        if email is None or password is None or email == "" or password == "":
            return create_response(
                message={"error": "missing email or password"},
                status_code=STATUS_CODES["bad_request"],
            )

        try:
            # Forward login request to the authentication service
            response = requests_post(
                f"http://{AUTH_SERVER_HOST}:{AUTH_SERVER_PORT}/auth/login",
                json={"email": email, "password": password},
                timeout=5,
            )
        except RequestException as ex:

            # Log the error
            log(
                log_type="error",
                message=f"Authentication service unavailable: {str(ex)}",
                origin_name=API_SERVER_NAME_IN_LOG,
                origin_host=API_SERVER_HOST,
                message_id="UserAction",
                structured_data={
                    "endpoint": UserLogin.ENDPOINT_PATHS[0],
                    "verb": "POST",
                },
            )

            # Return error response
            return create_response(
                message={"error": "Authentication service unavailable"},
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
                origin_name=API_SERVER_NAME_IN_LOG,
                origin_host=API_SERVER_HOST,
                message_id="UserAction",
                structured_data={
                    "endpoint": UserLogin.ENDPOINT_PATHS[0],
                    "verb": "POST",
                },
            )
            return create_response(
                message={"error": "Invalid credentials"},
                status_code=STATUS_CODES["unauthorized"],
            )

        elif response.status_code == STATUS_CODES["bad_request"]:
            log(
                log_type="error",
                message=f"Bad request during login for email: {email}",
                origin_name=API_SERVER_NAME_IN_LOG,
                origin_host=API_SERVER_HOST,
                message_id="UserAction",
                structured_data={
                    "endpoint": UserLogin.ENDPOINT_PATHS[0],
                    "verb": "POST",
                },
            )
            return create_response(
                message={"error": "Bad request"},
                status_code=STATUS_CODES["bad_request"],
            )

        elif response.status_code == STATUS_CODES["internal_error"]:
            log(
                log_type="error",
                message=f"Internal error during login for email: {email}",
                origin_name=API_SERVER_NAME_IN_LOG,
                origin_host=API_SERVER_HOST,
                message_id="UserAction",
                structured_data={
                    "endpoint": UserLogin.ENDPOINT_PATHS[0],
                    "verb": "POST",
                },
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
                origin_name=API_SERVER_NAME_IN_LOG,
                origin_host=API_SERVER_HOST,
                message_id="UserAction",
                structured_data=f"[endpoint='{UserLogin.ENDPOINT_PATHS[0]} verb='POST']",
            )
            return create_response(
                message={"error": "Unexpected error during login"},
                status_code=STATUS_CODES["internal_error"],
            )

    def options(self) -> Response:
        """
        Handle OPTIONS request for CORS preflight.
        This method returns the allowed HTTP methods for this endpoint.
        """
        return handle_options_request(resource_class=self)


api.add_resource(User, *User.ENDPOINT_PATHS)
api.add_resource(UserLogin, *UserLogin.ENDPOINT_PATHS)
