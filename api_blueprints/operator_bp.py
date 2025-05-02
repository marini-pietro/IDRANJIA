from os.path import basename as os_path_basename
from flask import Blueprint, request, Response
from flask_restful import Api, Resource
from flask_jwt_extended import get_jwt_identity, jwt_required
from typing import Dict, Union, Any
from blueprints_utils import (
    check_authorization,
    fetchone_query,
    execute_query,
    log,
    create_response,
    has_valid_json,
    is_input_safe,
    get_class_http_verbs,
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
operator_bp = Blueprint(BP_NAME, __name__)
api = Api(operator_bp)


class Operator(Resource):

    ENDPOINT_PATHS = [f"/{BP_NAME}", f"/{BP_NAME}/<int:id_>", f"/{BP_NAME}/<string:CF>"]

    @jwt_required()
    def get(self, id_) -> Response:
        """
        Get the information of an operator from the database.
        """

        # Validate the id_
        if not isinstance(id_, int) or id_ < 0:
            return create_response(
                message={"error": "id must be a positive integer"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Get the data
        operator = fetchone_query(
            "SELECT CF, nome, cognome FROM operatori WHERE id = %s", (id_,)
        )

        # Check if the result is empty
        if not operator:
            return create_response(
                message={"error": "No data found for the provided ID."},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            type="info",
            message=f'User {get_jwt_identity().get("email")} fetched operator with id {id_}',
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{Operator.ENDPOINT_PATHS[0]}' verb='GET']",
        )

        # Return the operator as a JSON response
        return create_response(message=operator, status_code=STATUS_CODES["ok"])

    @jwt_required()
    def post(self) -> Response:
        """
        Create a new operator row in the database.
        """

        # Validate request
        data: Union[str, Dict[str, Any]] = has_valid_json(request)
        if isinstance(data, str):
            return create_response(
                message={"error": data}, status_code=STATUS_CODES["bad_request"]
            )

        # Check for sql injection
        if not is_input_safe(data):
            return create_response(
                message={"error": "invalid input, suspected sql injection"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Gather the data
        cf = data.get("CF")
        name = data.get("nome")
        surname = data.get("cognome")

        # Validate the data
        if not all([cf, name, surname]):
            return create_response(
                message={"error": "missing required fields."},
                status_code=STATUS_CODES["bad_request"],
            )
        if not isinstance(cf, str):  # TODO add regex check for CF
            return create_response(
                message={"error": "cf must be string value."},
                status_code=STATUS_CODES["bad_request"],
            )
        if not isinstance(name, str):
            return create_response(
                message={"error": "name must be string value."},
                status_code=STATUS_CODES["bad_request"],
            )
        if not isinstance(surname, str):
            return create_response(
                message={"error": "surname must be string value."},
                status_code=STATUS_CODES["bad_request"],
            )

        # Check if the operator already exists
        existing_operator = fetchone_query(
            "SELECT nome FROM operatori WHERE CF = %s", (cf,)
        )  # Column in SELECT is not important, we just need to check if the row exists
        if existing_operator:
            return create_response(
                message={"error": "operator already exists."},
                status_code=STATUS_CODES["bad_request"],
            )

        # Insert the new operator into the database
        lastrowid = execute_query(
            "INSERT INTO operatori (CF, nome, cognome) VALUES (%s, %s, %s)",
            (cf, name, surname),
        )

        # Log the action
        log(
            type="info",
            message=f'User {get_jwt_identity().get("email")} created operator with id {lastrowid}',
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[{Operator.ENDPOINT_PATHS[0]} Verb POST]",
        )

        # Return the new operator as a JSON response
        return create_response(
            message={
                "outcome": "operator successfully created",
                "location": f"http://{API_SERVER_HOST}:{API_SERVER_PORT}/{Operator.ENDPOINT_PATHS[0]}/{lastrowid}",
            },
            status_code=STATUS_CODES["created"],
        )

    @jwt_required()
    def patch(self) -> Response: ...

    @jwt_required()
    def delete(self, CF) -> Response:
        """
        Delete an operator from the database.
        """

        # Validate the CF
        if not isinstance(CF, str):  # TODO add regex check for CF
            return create_response(
                message={"error": "CF must be a string value."},
                status_code=STATUS_CODES["bad_request"],
            )

        # Check if the ID exists in the database
        operator = fetchone_query(
            "SELECT nome FROM operatori WHERE cf = %s", (CF,)
        )  # Column in SELECT is not important, we just need to check if the cf exists
        if operator:
            return create_response(
                message={"error": "CF already exist in the database"},
                status_code=STATUS_CODES["not_found"],
            )

        # Execute the query
        execute_query("DELETE FROM operatori WHERE CF = %s", (CF,))

        # Log the action
        log(
            type="info",
            message=f'User {get_jwt_identity().get("email")} deleted opearator with cf {CF}',
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[{Operator.ENDPOINT_PATHS[1]} Verb DELETE]",
        )

        # Return the response
        return create_response(
            message={"outcome": "successfully deleted operator"},
            status_code=STATUS_CODES["ok"],
        )

    @jwt_required()
    def options(self) -> Response:
        # Define allowed methods
        allowed_methods = get_class_http_verbs(type(self))

        # Create the response
        response = Response(status=STATUS_CODES["ok"])
        response.headers["Allow"] = ", ".join(allowed_methods)
        response.headers["Access-Control-Allow-Origin"] = (
            "*"  # Adjust as needed for CORS
        )
        response.headers["Access-Control-Allow-Methods"] = ", ".join(allowed_methods)
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"

        return response


api.add_resource(Operator, *Operator.ENDPOINT_PATHS)
