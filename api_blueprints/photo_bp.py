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
    handle_options_request,
    build_update_query_from_filters,
    get_hateos_location_string,
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
photo_bp = Blueprint(BP_NAME, __name__)
api = Api(photo_bp)


class Photo(Resource):

    ENDPOINT_PATHS = [f"/{BP_NAME}", f"/{BP_NAME}/<int:id_>"]

    @jwt_required()
    def get(self, hydrant_id) -> Response:
        """
        Get a photo by ID of the hydrant that it represents.
        """

        # Validate the hydrant_id
        if not isinstance(hydrant_id, int) or hydrant_id < 0:
            return create_response(
                message={"error": "hydrant id_ must be positive integer"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Check that hydrant exists
        hydrant = fetchone_query(
            query="SELECT stato FROM hydrants WHERE id = %s", params=(hydrant_id,)
        )
        if hydrant is None:
            return create_response(
                message={"error": "hydrant not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Get the data
        photos = fetchall_query(
            query="SELECT posizione, data FROM photos WHERE id_idrante = %s",
            params=(hydrant_id,),
        )

        # Check if photos exist
        if photos is None:
            return create_response(
                message={"error": "no photos found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} fetched photos with hydrant id_ {hydrant_id}",
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{Photo.ENDPOINT_PATHS[0]}' verb='GET']",
        )

        # Return the photos as a JSON response
        return create_response(message=photos, status_code=STATUS_CODES["ok"])

    @jwt_required()
    def post(self) -> Response:
        """
        Create a new photo row in the database.
        """

        # Gather data
        data = request.get_json()
        hydrant_id = data.get("id_idrante")
        position = data.get("posizione")
        date = data.get("data")

        # Validate the data
        if not all([hydrant_id, position, date]):
            return create_response(
                message={"error": "missing required fields."},
                status_code=STATUS_CODES["bad_request"],
            )
        if not (
            isinstance(hydrant_id, int)
            and hydrant_id >= 0
            or isinstance(hydrant_id, str)
            and hydrant_id.isdigit()
        ):
            return create_response(
                message={
                    "error": "hydrant id must be positive integer or numeric string"
                },
                status_code=STATUS_CODES["bad_request"],
            )
        if not isinstance(position, str):
            return create_response(
                message={"error": "position must be string value."},
                status_code=STATUS_CODES["bad_request"],
            )
        if not isinstance(date, str):
            return create_response(
                message={"error": "date must be string value."},
                status_code=STATUS_CODES["bad_request"],
            )

        # Perform casting operations if needed
        if isinstance(hydrant_id, str):
            hydrant_id = int(hydrant_id)
        date = parse_date_string(date)

        # Check that hydrant exists
        hydrant = fetchone_query(
            "SELECT id_ FROM hydrants WHERE id_ = %s", (hydrant_id,)
        )
        if not hydrant:
            return create_response(
                message={"error": "hydrant not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Check if the photo already exists
        existing_photo = fetchone_query(
            "SELECT * FROM photos WHERE id_idrante = %s AND posizione = %s AND data = %s",
            (hydrant_id, position, date),
        )
        if existing_photo:
            return create_response(
                message={"error": "photo already exists."},
                status_code=STATUS_CODES["bad_request"],
            )

        # Insert the new photo into the database
        insert_query = (
            "INSERT INTO photos (id_idrante, posizione, data) VALUES (%s, %s, %s)"
        )
        lastrowid = execute_query(insert_query, (hydrant_id, position, date))

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} created photo with hydrant id_ {hydrant_id}",
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[{Photo.ENDPOINT_PATHS[0]} Verb POST]",
        )

        # Return the response
        return create_response(
            message={
                "outcome": "photo successfully created",
                "location": f"http://{API_SERVER_HOST}:{API_SERVER_PORT}/{Photo.ENDPOINT_PATHS[0]}/{lastrowid}",
            },
            status_code=STATUS_CODES["created"],
        )

    @jwt_required()
    def patch(self, id_) -> Response:
        """
        Update a photo by ID.
        """

        # Validate the ID
        if id_ < 0:
            return create_response(
                message={"error": "photo id_ must be positive integer"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Check that the photo exists
        photo = fetchone_query(
            query="SELECT data FROM photos WHERE id_foto = %s",
            params=(
                id_,
            ),  # Only fecth to check for existence (select column could be any)
        )
        if photo is None:
            return create_response(
                message={"error": "photo with specfied id not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Gather data
        data = request.get_json()
        position = data.get("posizione")
        data = data.get("data")
        id_idrante = data.get("id_idrante")

        # Validate the data
        if any(var is None for var in [position, data]):
            return create_response(
                message={"error": "missing required fields."},
                status_code=STATUS_CODES["bad_request"],
            )
        if position is not None and isinstance(position, str):
            return create_response(
                message={"error": "position must be string value."},
                status_code=STATUS_CODES["bad_request"],
            )
        if not any(
            position.endswith(ext)
            for ext in [
                ".jpg",
                ".jpeg",
                ".png",
                ".gif",
                ".webp",
                ".bmp",
                ".svg",
                ".ico",
                ".tiff",
            ]
        ):
            return create_response(
                message={
                    "error": "position must be a file name with a valid image extension."
                },
                status_code=STATUS_CODES["bad_request"],
            )
        if data is not None and isinstance(data, str):
            return create_response(
                message={"error": "date must be string value."},
                status_code=STATUS_CODES["bad_request"],
            )
        if id_idrante is not None and (
            isinstance(id_idrante, int)
            and id_idrante >= 0
            or isinstance(id_idrante, str)
            and id_idrante.isdigit()
        ):
            return create_response(
                message={
                    "error": "hydrant id must be positive integer or numeric string"
                },
                status_code=STATUS_CODES["bad_request"],
            )

        # Perform casting operations if needed
        if isinstance(data, str):
            data = parse_date_string(data)
        if isinstance(id_idrante, str):
            id_idrante = int(id_idrante)

        # Check that hydrant exists
        hydrant = fetchone_query(
            "SELECT stato FROM idranti WHERE id = %s", (id_idrante,)
        )

        if hydrant is None:
            return create_response(
                message={"error": "hydrant not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Check that specified location is not already taken
        photo = fetchone_query(
            "SELECT data FROM foto WHERE posizione = %s",
            (position,),
        )
        if photo is None:
            return create_response(
                message={"error": "photo with specified position already exists"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} updated photo with id_ {id_}",
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{Photo.ENDPOINT_PATHS[0]}' verb='PATCH']",
        )

        # Update the photo in the database
        query, params = build_update_query_from_filters(
            data=data, table_name="photos", pk_column="id_foto", pk_value=id_
        )

        # Execute the update query
        execute_query(query, params)

        # Return the response
        return create_response(
            message={
                "outcome": "photo successfully updated",
                "location": get_hateos_location_string(bp_name=BP_NAME, id_=id_),
            },
            status_code=STATUS_CODES["ok"],
        )

    @jwt_required()
    def delete(self, id_) -> Response:
        """
        Delete a photo by ID.
        """

        # Validate the ID
        if id_ < 0:
            return create_response(
                message={"error": "photo id_ must be positive integer"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Delete the photo from the database
        _, rows_affected = execute_query(
            query="DELETE FROM photos WHERE id_foto = %s", params=(id_,)
        )

        # Check if any rows were affected
        if rows_affected == 0:
            return create_response(
                message={"error": "photo with specfied id not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} deleted photo with id_ {id_}",
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[endpoint='{request.path}' verb='{request.method}']",
        )

        # Return the response
        return create_response(
            message={"outcome": "photo successfully deleted"},
            status_code=STATUS_CODES["ok"],
        )

    @jwt_required()
    def options(self) -> Response:
        return handle_options_request(resource_class=self)


api.add_resource(Photo, *Photo.ENDPOINT_PATHS)
