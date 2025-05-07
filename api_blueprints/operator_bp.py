from os.path import basename as os_path_basename
from flask import Blueprint, request, Response
from flask_restful import Api, Resource
from flask_jwt_extended import get_jwt_identity, jwt_required
from typing import Dict, Union, Any
from .blueprints_utils import (
    check_authorization,
    fetchone_query,
    execute_query,
    log,
    create_response,
    get_hateos_location_string,
    build_update_query_from_filters,
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
        if operator is None:
            return create_response(
                message={"error": "no resource found with specified id"},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} fetched operator with id {id_}",
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

        # Gather the data
        data = request.get_json()
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
        operator = fetchone_query(
            query="SELECT nome FROM operatori WHERE CF = %s", params=(cf,)
        )  # Column in SELECT is not important, we just need to check if the row exists
        if operator is not None:
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
            message=f"User {get_jwt_identity()} created operator with id {lastrowid}",
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{Operator.ENDPOINT_PATHS[0]}' verb='POST']",
        )

        # Return the new operator as a JSON response
        return create_response(
            message={
                "outcome": "operator successfully created",
                "location": get_hateos_location_string(bp_name=BP_NAME, id_=lastrowid),
            },
            status_code=STATUS_CODES["created"],
        )

    @jwt_required()
    def patch(self, id_) -> Response:
        """
        Update an operator in the database by its ID.
        """

        # Validate the id
        if id_ < 0:
            return create_response(
                message={"error": "id must be a positive integer"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Check that the operator exists
        operator = fetchone_query(
            query="SELECT nome FROM operatori WHERE id = %s", params=(id_,)
        )
        if operator is None:
            return create_response(
                message={"error": "no resource found with specified id"},
                status_code=STATUS_CODES["not_found"],
            )

        # Gather the data
        data = request.get_json()
        cf = data.get("CF")
        nome = data.get("nome")
        cognome = data.get("cognome")

        # Validate the data
        if any(var is None for var in [cf, nome, cognome]):
            return create_response(
                message={"error": "missing required fields."},
                status_code=STATUS_CODES["bad_request"],
            )
        if cf is not None and isinstance(cf, str):  # TODO add regex check for CF
            return create_response(
                message={"error": "cf must be string value."},
                status_code=STATUS_CODES["bad_request"],
            )
        if nome is not None and isinstance(nome, str):
            return create_response(
                message={"error": "name must be string value."},
                status_code=STATUS_CODES["bad_request"],
            )
        if cognome is not None and isinstance(cognome, str):
            return create_response(
                message={"error": "surname must be string value."},
                status_code=STATUS_CODES["bad_request"],
            )

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} updated operator with id {id_}",
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{Operator.ENDPOINT_PATHS[0]}' verb='PATCH']",
        )

        # Build the update query
        query, params = build_update_query_from_filters(
            data=data,
            table_name="operatori",
            pk_column="CF",
            pk_value=cf,
        )

        # Execute the update query
        execute_query(query=query, params=params)

        # Return the response
        return create_response(
            message={
                "outcome": "successfully updated operator",
                "location": get_hateos_location_string(bp_name=BP_NAME, id_=id_),
            },
            status_code=STATUS_CODES["ok"],
        )

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

        # Execute the query
        _, rows_affected = execute_query(
            query="DELETE FROM operatori WHERE CF = %s", params=(CF,)
        )

        # Check if any rows were affected
        if rows_affected == 0:
            return create_response(
                message={"error": "no resource found with specified cf"},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} deleted opearator with cf {CF}",
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{Operator.ENDPOINT_PATHS[1]}' verb='DELETE']",
        )

        # Return the response
        return create_response(
            message={"outcome": "successfully deleted operator"},
            status_code=STATUS_CODES["ok"],
        )

    @jwt_required()
    def options(self) -> Response:
        """
        Handle OPTIONS requests for CORS preflight checks.
        This method returns the allowed HTTP methods for the endpoint.
        """
        return handle_options_request(resource_class=self)


api.add_resource(Operator, *Operator.ENDPOINT_PATHS)
