from os.path import basename as os_path_basename
from flask import Blueprint, request, Response
from flask_restful import Api, Resource
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
    has_valid_json,
    is_input_safe,
    handle_options_request,
)
from config import (
    API_SERVER_HOST,
    API_SERVER_PORT,
    API_SERVER_NAME_IN_LOG,
    STATUS_CODES,
)

# Define constants
BP_NAME = os_path_basename(__file__).replace("_bp.py", "")

# Create the blueprint and API
user_bp = Blueprint(BP_NAME, __name__)
api = Api(user_bp)


class User(Resource):

    ENDPOINT_PATHS = [f"/{BP_NAME}", f"/{BP_NAME}/<string:email>"]

    @jwt_required()
    def get(self) -> Response: ...

    @jwt_required()
    def post(self) -> Response: ...

    @jwt_required()
    def patch(self) -> Response: ...

    @jwt_required()
    def put(self) -> Response: ...

    @jwt_required()
    def delete(self, email) -> Response:
        """
        Delete a user from the database by its email.
        """

        if not is_input_safe(email):
            return create_response(
                message={"error": "invalid email, suspected SQL injection"},
                status_code=STATUS_CODES["BAD_REQUEST"],
            )

        # Check that the user exists in the database
        user = fetchone_query(
            query="SELECT comune FROM utenti WHERE email = %s", # Only check for existence, no need to fetch all data
            params=(email,),
        )
        if user is None:
            return create_response(
                message={"error": "user not found"},
                status_code=STATUS_CODES["not_found"],
            )
        
        # Execute the delete query
        execute_query(
            query="DELETE FROM utenti WHERE email = %s",
            params=(email,),
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
        return handle_options_request(resource_class=self)


api.add_resource(User, *User.ENDPOINT_PATHS)
