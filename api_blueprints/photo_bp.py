from os.path import basename as os_path_basename
from flask import Blueprint, request, Response
from flask_restful import Api, Resource
from flask_jwt_extended import jwt_required
from flask_marshmallow import Marshmallow
from marshmallow import fields, ValidationError
from typing import Dict, Union, List, Any
from .blueprints_utils import (
    check_authorization,
    log,
    create_response,
    handle_options_request,
    get_hateos_location_string,
)
from api_server import ma
from config import (
    STATUS_CODES,
)
from models import db, Photo

# Define constants
BP_NAME = os_path_basename(__file__).replace("_bp.py", "")

# Create the blueprint and API
photo_bp = Blueprint(BP_NAME, __name__)
api = Api(photo_bp)


# Marshmallow Schemas
class PhotoSchema(ma.Schema):
    id_idrante = fields.Integer(required=True, validate=lambda x: x >= 0)
    posizione = fields.String(required=True)
    data = fields.Date(required=True)

photo_schema = PhotoSchema()


class PhotoResource(Resource):

    ENDPOINT_PATHS = [f"/{BP_NAME}", f"/{BP_NAME}/<int:id_>"]

    @jwt_required()
    def get(self, hydrant_id, identity) -> Response:
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
        hydrant = Photo.query.filter_by(id=hydrant_id).first()
        if hydrant is None:
            return create_response(
                message={"error": "hydrant not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Get the data
        photos: List[Dict[str, Any]] = (
            Photo.query.filter_by(id_idrante=hydrant_id)
            .with_entities(Photo.posizione, Photo.data)
            .all()
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
            message=f"User {identity} fetched photos with hydrant id_ {hydrant_id}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return the photos as a JSON response
        return create_response(message=photos, status_code=STATUS_CODES["ok"])

    @jwt_required()
    def post(self, identity) -> Response:
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
        hydrant_exists = db.session.query(
            db.session.query(Photo).filter_by(id_=hydrant_id).exists()
        ).scalar()
        if not hydrant_exists:
            return create_response(
            message={"error": "hydrant not found"},
            status_code=STATUS_CODES["not_found"],
            )

        # Check if the photo already exists
        photo_exists = db.session.query(
            db.session.query(Photo).filter_by(
                id_idrante=hydrant_id, posizione=position, data=date
            ).exists()
        ).scalar()
        if photo_exists:
            return create_response(
            message={"error": "photo already exists."},
            status_code=STATUS_CODES["bad_request"],
            )

        # Insert the new photo into the database
        new_photo = Photo(id_idrante=hydrant_id, posizione=position, data=date)
        db.session.add(new_photo)
        db.session.commit()

        # Log the action
        log(
            type="info",
            message=f"User {identity} created photo with hydrant id_ {hydrant_id}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return the response
        return create_response(
            message={
                "outcome": "photo successfully created",
                "location": get_hateos_location_string(bp_name=BP_NAME, id_=new_photo.id_foto),
            },
            status_code=STATUS_CODES["created"],
        )

    @jwt_required()
    def patch(self, id_, identity) -> Response:
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
        photo_exists = db.session.query(
            db.session.query(Photo).filter_by(id_foto=id_).exists()
        ).scalar()
        if not photo_exists:
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
        photo = Photo.query.get(id_)
        for key, value in data.items():
            setattr(photo, key, value)
        db.session.commit()

        # Log the action
        log(
            type="info",
            message=f"User {identity} updated photo with id_ {id_}",
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
    def delete(self, id_, identity) -> Response:
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
        photo = Photo.query.get(id_)
        if photo is None:
            return create_response(
                message={"error": "photo with specified id not found"},
                status_code=STATUS_CODES["not_found"],
            )
        db.session.delete(photo)
        db.session.commit()

        # Log the action
        log(
            type="info",
            message=f"User {identity} deleted photo with id_ {id_}",
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


api.add_resource(PhotoResource, *PhotoResource.ENDPOINT_PATHS)