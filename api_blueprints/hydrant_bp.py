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
    handle_options_request,
    build_update_query_from_filters,
    get_hateos_location_string,
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
hydrant_bp = Blueprint(BP_NAME, __name__)
api = Api(hydrant_bp)


class Hydrant(Resource):
    """
    Hydrant resource for managing hydrant data.
    This class provides methods to create, read, update, and delete hydrant records.
    """

    ENDPOINT_PATHS = [f"/{BP_NAME}", f"/{BP_NAME}/<int:id_>"]

    @jwt_required()
    def get(self, id_) -> Response:
        """
        Read hydrant data from the database.
        """

        # Validate the id_
        if not isinstance(id_, int) or id_ <= 0:
            return create_response(
                message={"error": "id_ must be positive integer"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Get the data
        hydrant: Dict[str, Any] = fetchone_query(
            "SELECT stato, latitudine, longitudine, comune, via, area_geo, tipo, accessibilità, email_ins FROM idranti WHERE id = %s",
            (id_,),
        )

        # Check if the result is empty
        if hydrant is None:
            return create_response(
                message={"error": "No data found for the provided ID."},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} fetched hydrant with id_ {id_}",
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{Hydrant.ENDPOINT_PATHS[0]}' verb='GET']",
        )

        # Return the hydrant as a JSON response
        return create_response(message=hydrant, status_code=STATUS_CODES["ok"])

    @jwt_required()
    def post(self) -> Response:
        """
        Create a new hydrant row in the database.
        """

        # Gather the data
        data = request.get_json()
        stato = data.get("stato")
        latitudine = data.get("latitudine")
        longitudine = data.get("longitudine")
        comune = data.get("comune")
        via = data.get("via")
        area_geo = data.get("area_geo")
        tipo = data.get("tipo")
        accessibilità = data.get("accessibilità")
        email_ins = get_jwt_identity()

        # Validate the data
        if not all(
            [stato, latitudine, longitudine, comune, via, area_geo, tipo, accessibilità]
        ):
            return create_response(
                message={"error": "missing required fields."},
                status_code=STATUS_CODES["bad_request"],
            )
        if not isinstance(stato, str):
            return create_response(
                message={"error": "stato must be string"},
                status_code=STATUS_CODES["bad_request"],
            )
        if not isinstance(latitudine, float):
            return create_response(
                message={"error": "latitudine must be float"},
                status_code=STATUS_CODES["bad_request"],
            )
        if not isinstance(longitudine, float):
            return create_response(
                message={"error": "longitudine must be float"},
                status_code=STATUS_CODES["bad_request"],
            )
        if not isinstance(comune, str):
            return create_response(
                message={"error": "comune must be string"},
                status_code=STATUS_CODES["bad_request"],
            )
        if not isinstance(via, str):
            return create_response(
                message={"error": "via must be string"},
                status_code=STATUS_CODES["bad_request"],
            )
        if not isinstance(area_geo, str):
            return create_response(
                message={"error": "area_geo must be string"},
                status_code=STATUS_CODES["bad_request"],
            )
        if not isinstance(tipo, str):
            return create_response(
                message={"error": "tipo must be string"},
                status_code=STATUS_CODES["bad_request"],
            )
        if not isinstance(accessibilità, str):
            return create_response(
                message={"error": "accessibilità must be string"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Check if the email exists in the database
        user: Dict[str, Any] = fetchone_query(
            "SELECT email FROM utenti WHERE email = %s", (email_ins,)
        )
        if user is None:
            return create_response(
                message={"error": "email found in JWT not present in database"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Check if the hydrant already exists
        hydrant: Dict[str, Any] = fetchone_query(
            "SELECT area_geo FROM idranti WHERE stato = %s AND latitudine = %s AND longitudine = %s",
            (stato, latitudine, longitudine),
        )
        if hydrant is not None:
            return create_response(
                message={
                    "error": "hydrant with provided stato, latitudine and longitudine already exists"
                },
                status_code=STATUS_CODES["bad_request"],
            )

        # Insert the new hydrant into the database
        lastrowid = execute_query(
            "INSERT INTO idranti (stato, latitudine, longitudine, "
            "comune, via, area_geo, "
            "tipo, accessibilità, email_ins) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                stato,
                latitudine,
                longitudine,
                comune,
                via,
                area_geo,
                tipo,
                accessibilità,
                email_ins,
            ),
        )

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} created hydrant with id_ {lastrowid}",
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{Hydrant.ENDPOINT_PATHS[0]}' verb='POST']",
        )

        # Return the response
        return create_response(
            message={
                "outcome": "successfully created new hydrant",
                "location": get_hateos_location_string(bp_name=BP_NAME, id_=lastrowid),
            },
            status_code=STATUS_CODES["created"],
        )

    @jwt_required()
    def patch(self, id_) -> Response:
        """
        Update a hydrant row in the database by its ID.
        """

        # Validate the ID
        if id_ <= 0:
            return create_response(
                message={"error": "id_ must be positive integer"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Check if the ID exists in the database
        hydrant: Dict[str, Any] = fetchone_query(
            "SELECT stato FROM idranti WHERE id = %s", (id_,)
        )
        if hydrant is None:
            return create_response(
                message={"error": "specified resource does not exist in the database"},
                status_code=STATUS_CODES["not_found"],
            )

        # Gather the data
        data = request.get_json()
        stato = data.get("stato")
        latitudine = data.get("latitudine")
        longitudine = data.get("longitudine")
        comune = data.get("comune")
        via = data.get("via")
        area_geo = data.get("area_geo")
        tipo = data.get("tipo")
        accessibilità = data.get("accessibilità")

        # Validate the data
        if any(
            var is None
            for var in [
                stato,
                latitudine,
                longitudine,
                comune,
                via,
                area_geo,
                tipo,
                accessibilità,
            ]
        ):
            return create_response(
                message={"error": "missing required fields."},
                status_code=STATUS_CODES["bad_request"],
            )
        if stato is not None and isinstance(stato, str):
            return create_response(
                message={"error": "stato must be string"},
                status_code=STATUS_CODES["bad_request"],
            )
        if latitudine is not None and isinstance(latitudine, float):
            return create_response(
                message={"error": "latitudine must be float"},
                status_code=STATUS_CODES["bad_request"],
            )
        if longitudine is not None and isinstance(longitudine, float):
            return create_response(
                message={"error": "longitudine must be float"},
                status_code=STATUS_CODES["bad_request"],
            )
        if comune is not None and isinstance(comune, str):
            return create_response(
                message={"error": "comune must be string"},
                status_code=STATUS_CODES["bad_request"],
            )
        if via is not None and isinstance(via, str):
            return create_response(
                message={"error": "via must be string"},
                status_code=STATUS_CODES["bad_request"],
            )
        if area_geo is not None and isinstance(area_geo, str):
            return create_response(
                message={"error": "area_geo must be string"},
                status_code=STATUS_CODES["bad_request"],
            )
        if tipo is not None and isinstance(tipo, str):
            return create_response(
                message={"error": "tipo must be string"},
                status_code=STATUS_CODES["bad_request"],
            )
        if accessibilità is not None and isinstance(accessibilità, str):
            return create_response(
                message={"error": "accessibilità must be string"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Check if the email exists in the database
        email_ins = get_jwt_identity()
        user: Dict[str, Any] = fetchone_query(
            "SELECT email FROM utenti WHERE email = %s", (email_ins,)
        )
        if user is None:
            return create_response(
                message={"error": "email found in JWT not present in database"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Build the update query
        query, params = build_update_query_from_filters(
            data=data, table_name="idranti", pk_column="id", pk_value=id_
        )

        # Execute the update query
        execute_query(query, params)

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} updated hydrant with id {id_}",
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{Hydrant.ENDPOINT_PATHS[0]}' verb='PATCH']",
        )

        # Return the response
        return create_response(
            message={
                "outcome": "successfully updated hydrant",
                "location": get_hateos_location_string(bp_name=BP_NAME, id_=id_),
            },
            status_code=STATUS_CODES["ok"],
        )

    @jwt_required()
    def delete(self, id_) -> Response:
        """
        Delete a hydrant row by ID.
        ID is passed as a path variable integer.
        """

        # Validate the ID
        if id_ < 0:
            return create_response(
                message={"error": "id_ must be positive integer."},
                status_code=STATUS_CODES["bad_request"],
            )

        # Execute the query
        _, rows_affected = execute_query("DELETE FROM idranti WHERE id = %s", (id_,))

        # Check if any rows were affected
        if rows_affected == 0:
            return create_response(
                message={"error": "specified resource does not exist in the database"},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} deleted hydrant with id {id_}",
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{Hydrant.ENDPOINT_PATHS[1]}' verb='DELETE']",
        )

        # Return the response
        return create_response(
            message={"outcome": "successfully deleted hydrant"},
            status_code=STATUS_CODES["ok"],
        )

    @jwt_required()
    def options(self) -> Response:
        return handle_options_request(resource_class=self)


api.add_resource(Hydrant, *Hydrant.ENDPOINT_PATHS)
