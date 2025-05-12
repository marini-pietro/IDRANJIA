from os.path import basename as os_path_basename
from flask import Blueprint, request, Response
from flask_restful import Api, Resource
from flask_jwt_extended import get_jwt_identity, jwt_required
from flask_marshmallow import Marshmallow
from marshmallow import fields, ValidationError
from typing import Dict, Union, List, Any
from .blueprints_utils import (
    check_authorization,
    fetchone_query,
    fetchall_query,
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

# Initialize Marshmallow
ma = Marshmallow()

# Define constants
BP_NAME = os_path_basename(__file__).replace("_bp.py", "")

# Create the blueprint and API
photo_bp = Blueprint(BP_NAME, __name__)
api = Api(photo_bp)


# Marshmallow Schemas
class PhotoSchema(ma.Schema):
    id_idrante = fields.Integer(required=True, validate=lambda x: x >= 0)
    posizione = fields.String(required=True)
    data = fields.String(required=True)

photo_schema = PhotoSchema()


class Photo(Resource):

    ENDPOINT_PATHS = [f"/{BP_NAME}", f"/{BP_NAME}/<int:id_>"]

    @jwt_required()
    def get(self, hydrant_id) -> Response:
        """
        Get a photo by ID of the hydrant that it represents.
        """

        # Validate the hydrant_id
        if hydrant_id < 0:
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
        photos: List[Dict[str, Any]] = fetchall_query(
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
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return the photos as a JSON response
        return create_response(message=photos, status_code=STATUS_CODES["ok"])

    @jwt_required()
    def post(self) -> Response:
        """
        Create a new photo row in the database.
        """

        # Validate and deserialize input data
        try:
            data = photo_schema.load(request.get_json())
        except ValidationError as err:
            return create_response(
                message={"error": err.messages},
                status_code=STATUS_CODES["bad_request"],
            )

        hydrant_id = data["id_idrante"]
        position = data["posizione"]
        date = data["data"]

        # Check that hydrant exists
        hydrant: Dict[str, Any] = fetchone_query(
            "SELECT id_ FROM hydrants WHERE id_ = %s", (hydrant_id,)
        )
        if hydrant is None:
            return create_response(
                message={"error": "hydrant not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Check if the photo already exists
        existing_photo: Dict[str, Any] = fetchone_query(
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
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return the response
        return create_response(
            message={
                "outcome": "photo successfully created",
                "location": get_hateos_location_string(bp_name=BP_NAME, id_=lastrowid),
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
            params=(id_,),
        )
        if photo is None:
            return create_response(
                message={"error": "photo with specified id not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Validate and deserialize input data
        try:
            data = photo_schema.load(request.get_json())
        except ValidationError as err:
            return create_response(
                message={"error": err.messages},
                status_code=STATUS_CODES["bad_request"],
            )

        # Update the photo in the database
        query, params = build_update_query_from_filters(
            data=data, table_name="photos", pk_column="id_foto", pk_value=id_
        )
        execute_query(query, params)

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} updated photo with id_ {id_}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

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
                message={"error": "photo with specified id not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            type="info",
            message=f"User {get_jwt_identity()} deleted photo with id_ {id_}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
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