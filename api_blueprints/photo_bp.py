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
    has_valid_json,
    is_input_safe,
    get_class_http_verbs,
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
        hydrant = fetchone_query("SELECT id_ FROM hydrants WHERE id_ = %s", (hydrant_id,))
        if not hydrant:
            return create_response(
                message={"error": "hydrant not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Get the data
        photos = fetchall_query(
            "SELECT posizione, data FROM photos WHERE idI = %s", (hydrant_id,)
        )

        # Check if photos exist
        if not photos:
            return create_response(
                message={"error": "no photos found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            type="info",
            message=f'User {get_jwt_identity().get("email")} fetched photos with hydrant id_ {hydrant_id}',
            origin_name=API_SERVER_NAME_IN_LOG,
            origin_host=API_SERVER_HOST,
            origin_port=API_SERVER_PORT,
            structured_data=f"[{Photo.ENDPOINT_PATHS[0]} Verb GET]",
        )

        # Return the photos as a JSON response
        return create_response(message=photos, status_code=STATUS_CODES["ok"])

    @jwt_required()
    def post(self) -> Response:
        """
        Create a new photo row in the database.
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

        # Gather data
        hydrant_id = data.get("idI")
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
        hydrant = fetchone_query("SELECT id_ FROM hydrants WHERE id_ = %s", (hydrant_id,))
        if not hydrant:
            return create_response(
                message={"error": "hydrant not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Check if the photo already exists
        existing_photo = fetchone_query(
            "SELECT * FROM photos WHERE idI = %s AND posizione = %s AND data = %s",
            (hydrant_id, position, date),
        )
        if existing_photo:
            return create_response(
                message={"error": "photo already exists."},
                status_code=STATUS_CODES["bad_request"],
            )

        # Insert the new photo into the database
        insert_query = "INSERT INTO photos (idI, posizione, data) VALUES (%s, %s, %s)"
        lastrowid = execute_query(insert_query, (hydrant_id, position, date))

        # Log the action
        log(
            type="info",
            message=f'User {get_jwt_identity().get("email")} created photo with hydrant id_ {hydrant_id}',
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
    def patch(self, id_) -> Response: ...

    @jwt_required()
    def delete(self, id_) -> Response: ...

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


api.add_resource(Photo, *Photo.ENDPOINT_PATHS)
