from os.path import basename as os_path_basename
from flask import Blueprint, request, Response
from flask_restful import Api, Resource
from flask_jwt_extended import get_jwt_identity, jwt_required
from typing import Dict, Union, Any
from flask_marshmallow import Marshmallow
from marshmallow import fields, ValidationError
from .blueprints_utils import (
    check_authorization,
    fetchone_query,
    execute_query,
    log,
    create_response,
    build_update_query_from_filters,
    get_hateos_location_string,
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
control_bp = Blueprint(BP_NAME, __name__)
api = Api(control_bp)

# Initialize Marshmallow
ma = Marshmallow()

# Define schemas
class ControlSchema(ma.Schema):
    tipo = fields.String(required=True)
    esito = fields.Boolean(required=True)
    data = fields.Date(required=True)
    id_idrante = fields.Integer(required=True)

control_schema = ControlSchema()

class Control(Resource):

    ENDPOINT_PATHS = [f"/{BP_NAME}", f"/{BP_NAME}/<int:id_>"]

    @jwt_required()
    def get(self, id_) -> Response:
        """
        Get a control row data by ID.
        ID is passed as a path variable integer.
        """

        # Validate the ID
        if id_ <= 0:
            return create_response(
                message={"error": "control id must be positive integer."},
                status_code=STATUS_CODES["BAD_REQUEST"],
            )

        # Get the data
        control: Dict[str, Any] = fetchone_query(
            query="SELECT tipo, esito, data, id_idrante FROM controlli WHERE id_controllo = %s",
            params=(id_,),
        )

        # Check if the result is empty
        if control is None:
            return create_response(
                message={"error": "No data found for the provided ID."},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} fetched control with id {id_}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return the control as a JSON response
        return create_response(message=control, status_code=STATUS_CODES["ok"])

    @jwt_required()
    def post(self) -> Response:
        """
        Create a new row in control table.
        The data is passed as a JSON body.
        """
        try:
            # Validate and deserialize input
            data = control_schema.load(request.get_json())
        except ValidationError as err:
            return create_response(
                message={"error": err.messages},
                status_code=STATUS_CODES["bad_request"],
            )

        tipo = data["tipo"]
        esito = data["esito"]
        data_esecuzione = data["data"]
        id_idrante = data["id_idrante"]

        # Check that the id_idrante exists in the database
        hydrant: Dict[str, Any] = fetchone_query(
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
            params=(tipo, esito, data_esecuzione, id_idrante),
        )

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} created control with id_ {lastrowid}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
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
        try:
            # Validate and deserialize input
            data = control_schema.load(request.get_json())
        except ValidationError as err:
            return create_response(
                message={"error": err.messages},
                status_code=STATUS_CODES["bad_request"],
            )
        
        # Check that the control exists in the database
        control: Dict[str, Any] = fetchone_query(
            query="SELECT tipo FROM controlli WHERE id_controllo = %s", params=(id_,)
        )  # Column in SELECT is not important, we just need to check if the id_ exists
        if control is None:
            return create_response(
                message={"error": "specified resource does not exist in the database"},
                status_code=STATUS_CODES["not_found"],
            )

        # Gather the data
        tipo: str = data.get("tipo")
        esito: bool = data.get("esito")
        data_esecuzione = data.get("data")
        id_idrante: int = data.get("id_idrante")

        # Check that the id_idrante exists in the database
        hydrant: Dict[str, Any] = fetchone_query(
            query="SELECT stato FROM idranti WHERE id = %s", params=(id_idrante,)
        )  # Column in SELECT is not important, we just need to check if the id_ exists
        if hydrant is None:
            return create_response(
                message={"error": "specified hydrant does not exist in the database"},
                status_code=STATUS_CODES["not_found"],
            )

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
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
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
        if id_ < 0:
            return create_response(
                message={"error": "id_ must be positive integer."},
                status_code=STATUS_CODES["bad_request"],
            )

        # Execute the query
        _, rows_affected = execute_query(
            query="DELETE FROM controlli WHERE id_controllo = %s", params=(id_,)
        )

        # Check if the row was deleted
        if rows_affected == 0:
            return create_response(
                message={"error": "specified resource does not exist in the database"},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} deleted control with id_ {id_}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
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
