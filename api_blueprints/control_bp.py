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
    validate_json_request,
    build_update_query_from_filters,
    parse_date_string,
    get_hateos_location_string,
    handle_options_request,
    parse_date_string,
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
control_bp = Blueprint(BP_NAME, __name__)
api = Api(control_bp)


class Control(Resource):

    ENDPOINT_PATHS = [f"/{BP_NAME}", f"/{BP_NAME}/<int:id_>"]

    @jwt_required()
    def get(self, id_) -> Response:
        """
        Get a control row data by ID.
        ID is passed as a path variable integer.
        """

        # Validate the ID
        if not isinstance(id_, int) or id_ <= 0:
            return create_response(STATUS_CODES["BAD_REQUEST"], "Invalid ID provided.")

        # Get the data
        control = fetchone_query(
            query="SELECT tipo, esito, data, id_idrante FROM controlli WHERE id_controllo = %s",
            params=(id_,),
        )

        # Check if the result is empty
        if not control:
            return create_response(
                message={"error": "No data found for the provided ID."},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} fetched control with id {id_}",
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{Control.ENDPOINT_PATHS[0]}' verb='GET']",
        )

        # Return the control as a JSON response
        return create_response(message=control, status_code=STATUS_CODES["ok"])

    @jwt_required()
    def post(self) -> Response:
        """
        Create a new row in control table.
        The data is passed as a JSON body.
        """

        # Validate request
        data: Union[str, Dict[str, Any]] = validate_json_request(request)
        if isinstance(data, str):
            return create_response(
                message={"error": data}, status_code=STATUS_CODES["bad_request"]
            )

        # Gather the data
        tipo: str = data.get("tipo")
        esito: bool = data.get("esito")
        data = parse_date_string(data.get("data"))
        id_idrante: int = data.get("id_idrante")

        # Validate the data
        if not all([tipo, esito, data, id_idrante]):
            return create_response(
                message={"error": "missing required fields."},
                status_code=STATUS_CODES["bad_request"],
            )
        if not isinstance(esito, bool):
            return create_response(
                message={"error": "esito must be boolean value"},
                status_code=STATUS_CODES["bad_request"],
            )
        if not isinstance(tipo, str):
            return create_response(
                message={"error": "tipo must be string value"},
                status_code=STATUS_CODES["bad_request"],
            )
        if not isinstance(data, str):
            return create_response(
                message={"error": "data must be string value"},
                status_code=STATUS_CODES["bad_request"],
            )
        if not (
            (isinstance(id_idrante, int) and id_idrante >= 0)
            or (isinstance(id_idrante, str) and id_idrante.isdigit())
        ):
            return create_response(
                message={
                    "error": "id_idrante must be a positive integer or a numeric string"
                },
                status_code=STATUS_CODES["bad_request"],
            )

        # Perform casting if needed
        if isinstance(id_idrante, str):
            id_idrante = int(id_idrante)
        data = parse_date_string(data)

        # Check that the id_idrante exists in the database
        hydrant = fetchone_query(
            query="SELECT stato FROM idranti WHERE id = %s", params=(id_idrante,)
        )  # Column in SELECT is not important, we just need to check if the id_ exists
        if hydrant is None:
            return create_response(
                message={"error": "id_idrante does not exist in the database"},
                status_code=STATUS_CODES["not_found"],
            )

        # Execute the query
        lastrowid = execute_query(
            query="INSERT INTO controlli (tipo, esito, data, id_idrante) "
            "VALUES (%s, %s, %s, %s)",
            params=(tipo, esito, data, id_idrante),
        )

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} created control with id_ {lastrowid}",
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{Control.ENDPOINT_PATHS[0]}' verb='POST']",
        )

        # Return the response
        return create_response(
            message={
                "outcome": "successfully created new control",
                "location": f"http://{API_SERVER_HOST}:{API_SERVER_PORT}/{Control.ENDPOINT_PATHS[0]}/{lastrowid}",
            },
            status_code=STATUS_CODES["created"],
        )

    @jwt_required()
    def patch(self, id_) -> Response:
        """
        Update a control row by ID.
        ID is passed as a path variable integer.
        The data is passed as a JSON body.
        """

        # Validate the ID
        if not isinstance(id_, int) or id_ < 0:
            return create_response(
                message={"error": "id must be a positive integer"},
                status_code=STATUS_CODES["BAD_REQUEST"],
            )

        # Check that the control exists in the database
        control = fetchone_query(
            query="SELECT tipo FROM controlli WHERE id_controllo = %s", params=(id_,)
        )  # Column in SELECT is not important, we just need to check if the id_ exists
        if control is None:
            return create_response(
                message={"error": "specified resource does not exist in the database"},
                status_code=STATUS_CODES["not_found"],
            )

        # Validate request
        data: Union[str, Dict[str, Any]] = validate_json_request(request)
        if isinstance(data, str):
            return create_response(
                message={"error": data}, status_code=STATUS_CODES["bad_request"]
            )

        # Gather the data
        tipo: str = data.get("tipo")
        esito: bool = data.get("esito")
        data = parse_date_string(data.get("data"))
        id_idrante: int = data.get("id_idrante")

        # Validate the data
        if any(var is None for var in [tipo, esito, data, id_idrante]):
            return create_response(
                message={"error": "missing required fields."},
                status_code=STATUS_CODES["bad_request"],
            )
        if tipo is not None and isinstance(tipo, str):
            return create_response(
                message={"error": "tipo must be string value"},
                status_code=STATUS_CODES["bad_request"],
            )
        if esito is not None and isinstance(esito, bool):
            return create_response(
                message={"error": "esito must be boolean value"},
                status_code=STATUS_CODES["bad_request"],
            )
        if data is not None and isinstance(data, str):
            return create_response(
                message={"error": "data must be string value"},
                status_code=STATUS_CODES["bad_request"],
            )
        if id_idrante is not None and (
            (isinstance(id_idrante, int) and id_idrante >= 0)
            or (isinstance(id_idrante, str) and id_idrante.isdigit())
        ):
            return create_response(
                message={
                    "error": "id_idrante must be a positive integer or a numeric string"
                },
                status_code=STATUS_CODES["bad_request"],
            )

        # Perform casting if needed
        if isinstance(id_idrante, str):
            id_idrante = int(id_idrante)

        # Check that the id_idrante exists in the database
        hydrant = fetchone_query(
            query="SELECT stato FROM idranti WHERE id = %s", params=(id_idrante,)
        )  # Column in SELECT is not important, we just need to check if the id_ exists
        if hydrant is None:
            return create_response(
                message={"error": "specified hydrant does not exist in the database"},
                status_code=STATUS_CODES["not_found"],
            )

        # Perform casting if needed
        if isinstance(id_idrante, str):
            id_idrante = int(id_idrante)

        # Build the query
        query, params = build_update_query_from_filters(
            data=data, table_name="controlli", id_column="id_controllo", id_value=id_
        )

        # Execute the query
        execute_query(query=query, params=params)

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} updated control with id {id_}",
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{Control.ENDPOINT_PATHS[0]}' verb='PATCH']",
        )

        # Return the response
        return create_response(
            message={
                "outcome": "successfully updated control",
                "location": get_hateos_location_string(bp_name=BP_NAME, id_=id_),
            },
            status_code=STATUS_CODES["ok"],
        )

    @jwt_required()
    def delete(self, id_) -> Response:
        """
        Delete a control row by ID.
        ID is passed as a path variable integer.
        """

        # Validate the ID
        if not isinstance(id_, int) or id_ < 0:
            return create_response(
                message={"error": "id_ must be positive integer."},
                status_code=STATUS_CODES["bad_request"],
            )

        # Check if the ID exists in the database
        control = fetchone_query(
            query="SELECT esito FROM controlli WHERE id_controllo = %s", params=(id_,)
        )  # Column in SELECT is not important, we just need to check if the id_ exists
        if control is None:
            return create_response(
                message={"error": "specified resource does not exist in the database"},
                status_code=STATUS_CODES["not_found"],
            )

        # Execute the query
        execute_query(
            query="DELETE FROM controlli WHERE id_controllo = %s", params=(id_,)
        )

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} deleted control with id_ {id_}",
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{Control.ENDPOINT_PATHS[1]}' verb='DELETE']",
        )

        # Return the response
        return create_response(
            message={"outcome": "successfully deleted control"},
            status_code=STATUS_CODES["ok"],
        )

    @jwt_required()
    def options(self) -> Response:
        return handle_options_request(resource_class=self)


api.add_resource(Control, *Control.ENDPOINT_PATHS)
