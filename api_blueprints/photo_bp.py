"""
Blueprint for managing hydrant photos.
This module provides endpoints to create, read, update, and delete photos associated with hydrants.
"""

from os.path import basename as os_path_basename
from flask import Blueprint, request, Response
from flask_restful import Api, Resource
from flask_jwt_extended import jwt_required
from marshmallow import fields, ValidationError
from typing import List
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
from models import db, Photo, Hydrant
from sqlalchemy import exists

# Define constants
BP_NAME = os_path_basename(__file__).replace("_bp.py", "")

# Create the blueprint and API
photo_bp = Blueprint(BP_NAME, __name__)
api = Api(photo_bp)


# Marshmallow Schemas
class PhotoSchema(ma.Schema):
    """
    Schema for validating and serializing photo data.
    This schema defines the fields required for a photo associated with a hydrant.
    """

    id_idrante = fields.Integer(required=True, validate=lambda x: x >= 0)
    posizione = fields.String(required=True)
    data = fields.Date(required=True)


# Create the schema instance
photo_schema = PhotoSchema()


class PhotoResource(Resource):
    """
    Photo resource for managing hydrant photos.
    This class provides methods to create, read, update, and delete photos associated with hydrants.
    """

    ENDPOINT_PATHS = [f"/{BP_NAME}/<int:id_>"]

    @jwt_required()
    def get(self, hydrant_id, identity) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Get photos by hydrant ID
        description: Retrieve all photos associated with a hydrant by its integer ID.
        parameters:
          - name: hydrant_id
            in: path
            required: true
            schema:
              type: integer
        responses:
          200:
            description: Photos found
          400:
            description: Invalid hydrant ID
          404:
            description: Hydrant or photos not found
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
                message={"error": "specified hydrant not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Get the data
        photos: List[Photo] = (
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
            log_type="info",
            message=f"User {identity} fetched photos with hydrant id {hydrant_id}",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return the photos as a JSON response
        return create_response(
            message=[photo.to_dict() for photo in photos],
            status_code=STATUS_CODES["ok"],
        )

    @jwt_required()
    def patch(self, id_, identity) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Update a photo by ID
        description: Update an existing photo record by its integer ID. Allows partial updates.
        parameters:
          - name: id_
            in: path
            required: true
            schema:
              type: integer
        requestBody:
          required: true
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Photo'
        responses:
          200:
            description: Photo updated
          400:
            description: Invalid input
          404:
            description: Photo not found
        """

        # Validate the ID
        if id_ < 0:
            return create_response(
                message={"error": "photo id_ must be positive integer"},
                status_code=STATUS_CODES["bad_request"],
            )

        photo = Photo.query.get(id_)
        if photo is None:
            return create_response(
                message={"error": "photo with specified id not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Validate and deserialize input data
        try:
            # Allow partial updates
            data = photo_schema.load(request.get_json(), partial=True)
        except ValidationError as err:
            return create_response(
                message={"error": err.messages},
                status_code=STATUS_CODES["bad_request"],
            )

        for key, value in data.items():
            setattr(photo, key, value)
        db.session.commit()

        # Log the action
        log(
            log_type="info",
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
        ---
        tags:
          - API Server (api_server)
        summary: Delete a photo by ID
        description: Delete a photo record from the database by its integer ID.
        parameters:
          - name: id_
            in: path
            required: true
            schema:
              type: integer
        responses:
          200:
            description: Photo deleted
          400:
            description: Invalid ID
          404:
            description: Photo not found
        """

        # Validate the ID
        if id_ < 0:
            return create_response(
                message={"error": "photo id_ must be positive integer"},
                status_code=STATUS_CODES["bad_request"],
            )

        photo = Photo.query.get(id_)
        if photo is None:
            return create_response(
                message={"error": "photo with specified id not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Delete the photo
        db.session.delete(photo)

        # Commit the changes to the database
        db.session.commit()

        # Log the action
        log(
            log_type="info",
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
        """
        ---
        tags:
          - API Server (api_server)
        summary: Get allowed HTTP methods for photo resource
        description: Returns the allowed HTTP methods for the photo resource endpoint.
        responses:
          200:
            description: Allowed methods returned
        """

        return handle_options_request(resource_class=self)


class PhotoPostResource(Resource):
    """
    Resource for creating new photos associated with hydrants.
    This class provides a method to create a new photo record.
    """

    ENDPOINT_PATHS = [f"/{BP_NAME}"]

    @jwt_required()
    def post(self, identity) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Create a new photo
        description: Create a new photo record associated with a hydrant.
        requestBody:
          required: true
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Photo'
        responses:
          201:
            description: Photo created
          400:
            description: Invalid input
          404:
            description: Hydrant not found
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

        # Optimized check that hydrant exists (should check Hydrant, not Photo)
        hydrant_exists: bool = db.session.query(
            exists().where(Hydrant.id == hydrant_id)
        ).scalar()
        if not hydrant_exists:
            return create_response(
                message={"error": "hydrant not found"},
                status_code=STATUS_CODES["not_found"],
            )

        # Check if the photo already exists
        photo_exists: bool = (
            Photo.query.filter_by(
                id_idrante=hydrant_id, posizione=position, data=date
            ).first()
            is not None
        )
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
            log_type="info",
            message=f"User {identity} created photo with hydrant id_ {hydrant_id}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return the response
        return create_response(
            message={
                "outcome": "photo successfully created",
                "location": get_hateos_location_string(
                    bp_name=BP_NAME, id_=new_photo.id_foto
                ),
            },
            status_code=STATUS_CODES["created"],
        )

    @jwt_required()
    def options(self) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Get allowed HTTP methods for photo resource
        description: Returns the allowed HTTP methods for the photo resource endpoint.
        responses:
          200:
            description: Allowed methods returned
        """

        return handle_options_request(resource_class=self)


# Register the resources with the API
api.add_resource(PhotoResource, *PhotoResource.ENDPOINT_PATHS)
api.add_resource(PhotoPostResource, *PhotoPostResource.ENDPOINT_PATHS)
