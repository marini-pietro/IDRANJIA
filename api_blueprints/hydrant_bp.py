from os.path import basename as os_path_basename
from flask import Blueprint, request, Response
from flask_restful import Api, Resource
from flask_jwt_extended import jwt_required
from typing import Dict, Union, Any
from .blueprints_utils import (
    check_authorization,
    log,
    create_response,
    handle_options_request,
    get_hateos_location_string,
)
from config import (
    API_SERVER_HOST,
    API_SERVER_PORT,
    API_SERVER_NAME_IN_LOG,
    STATUS_CODES,
)
from flask_marshmallow import Marshmallow
from marshmallow import fields, ValidationError
from models import db, Hydrant, User

# Define constants
BP_NAME = os_path_basename(__file__).replace("_bp.py", "")

# Create the blueprint and API
hydrant_bp = Blueprint(BP_NAME, __name__)
api = Api(hydrant_bp)

# Initialize Marshmallow
ma = Marshmallow(hydrant_bp)

# Define schemas
class HydrantSchema(ma.Schema):
    stato = fields.String(required=True)
    latitudine = fields.Float(required=True)
    longitudine = fields.Float(required=True)
    comune = fields.String(required=True)
    via = fields.String(required=True)
    area_geo = fields.String(required=True)
    tipo = fields.String(required=True)
    accessibilità = fields.String(required=True)


hydrant_schema = HydrantSchema()


class HydrantResource(Resource):
    """
    Hydrant resource for managing hydrant data.
    This class provides methods to create, read, update, and delete hydrant records.
    """

    ENDPOINT_PATHS = [f"/{BP_NAME}", f"/{BP_NAME}/<int:id_>"]

    @jwt_required()
    def get(self, id_, identity) -> Response:
        """
        Read hydrant data from the database.
        """

        # Validate the id_
        if id_ <= 0:
            return create_response(
                message={"error": "id_ must be positive integer"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Get the data
        hydrant: Hydrant = Hydrant.query.filter_by(id=id_).first()

        # Check if the result is empty
        if hydrant is None:
            return create_response(
                message={"error": "No data found for the provided ID."},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            type="info",
            message=f"User {identity} fetched hydrant with id_ {id_}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return the hydrant as a JSON response
        return create_response(message=hydrant.to_dict(), status_code=STATUS_CODES["ok"])

    @jwt_required()
    def post(self, identity) -> Response:
        """
        Create a new hydrant row in the database.
        """
        try:
            # Validate and deserialize input
            data = hydrant_schema.load(request.get_json())
        except ValidationError as err:
            return create_response(
                message={"error": err.messages},
                status_code=STATUS_CODES["bad_request"],
            )

        email_ins = identity

        # Check if the email exists in the database
        email_exists: bool = User.query.filter_by(email=email_ins).first() is not None
        if email_exists is False:
            return create_response(
            message={"error": "email found in JWT not present in database"},
            status_code=STATUS_CODES["bad_request"],
            )

        # Check if the hydrant already exists
        hydrant_exists: bool = db.session.query(
            db.func.exists().select().where(
                Hydrant.stato == data["stato"],
                Hydrant.latitudine == data["latitudine"],
                Hydrant.longitudine == data["longitudine"],
            )
        ).scalar()
        if hydrant_exists is False:
            return create_response(
            message={
                "error": "hydrant with provided stato, latitudine and longitudine already exists"
            },
            status_code=STATUS_CODES["bad_request"],
            )

        # Insert the new hydrant into the database
        new_hydrant = Hydrant(
            stato=data["stato"],
            latitudine=data["latitudine"],
            longitudine=data["longitudine"],
            comune=data["comune"],
            via=data["via"],
            area_geo=data["area_geo"],
            tipo=data["tipo"],
            accessibilità=data["accessibilità"],
            email_ins=email_ins,
        )
        db.session.add(new_hydrant)
        db.session.commit()

        # Log the action
        log(
            type="info",
            message=f"User {identity} created hydrant with id_ {new_hydrant.id}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return the response
        return create_response(
            message={
                "outcome": "successfully created new hydrant",
                "location": get_hateos_location_string(bp_name=BP_NAME, id_=new_hydrant.id),
            },
            status_code=STATUS_CODES["created"],
        )

    @jwt_required()
    def patch(self, id_, identity) -> Response:
        """
        Update a hydrant row in the database by its ID.
        """
        try:
            # Validate and deserialize input
            data = hydrant_schema.load(request.get_json())
        except ValidationError as err:
            return create_response(
                message={"error": err.messages},
                status_code=STATUS_CODES["bad_request"],
            )

        # Validate the ID
        if id_ <= 0:
            return create_response(
                message={"error": "id_ must be positive integer"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Check if the ID exists in the database
        hydrant = Hydrant.query.filter_by(id=id_).first()
        if not hydrant:
            return create_response(
            message={"error": "specified resource does not exist in the database"},
            status_code=STATUS_CODES["not_found"],
            )

        # Check if the email exists in the database
        email_ins = identity
        email_exists: bool = User.query.filter_by(email=email_ins).first() is not None
        if not email_exists:
            return create_response(
            message={"error": "email found in JWT not present in database"},
            status_code=STATUS_CODES["bad_request"],
            )

        # Update the hydrant object
        for key, value in data.items():
            setattr(hydrant, key, value)

        db.session.commit()

        # Log the action
        log(
            type="info",
            message=f"User {identity} updated hydrant with id {id_}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
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
    def delete(self, id_, identity) -> Response:
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
        hydrant = Hydrant.query.filter_by(id=id_).first()
        if hydrant is None:
            return create_response(
                message={"error": "specified resource does not exist in the database"},
                status_code=STATUS_CODES["not_found"],
            )

        db.session.delete(hydrant)
        db.session.commit()

        # Log the action
        log(
            type="info",
            message=f"User {identity} deleted hydrant with id {id_}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return the response
        return create_response(
            message={"outcome": "successfully deleted hydrant"},
            status_code=STATUS_CODES["ok"],
        )

    @jwt_required()
    def options(self) -> Response:
        return handle_options_request(resource_class=self)


api.add_resource(HydrantResource, *HydrantResource.ENDPOINT_PATHS)
