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
from api_server import ma
from config import (
    API_SERVER_HOST,
    API_SERVER_PORT,
    API_SERVER_NAME_IN_LOG,
    STATUS_CODES,
)
from marshmallow import fields, ValidationError
from models import db, Hydrant, User

# Define constants
BP_NAME = os_path_basename(__file__).replace("_bp.py", "")

# Create the blueprint and API
hydrant_bp = Blueprint(BP_NAME, __name__)
api = Api(hydrant_bp)


# Define schemas
class HydrantSchema(ma.Schema):
    """
    Schema for validating and serializing Hydrant data.
    This schema defines the fields required for a hydrant record.
    """

    id = fields.Integer(dump_only=True)  # read-only
    stato = fields.String(required=True)
    latitudine = fields.Float(required=True)
    longitudine = fields.Float(required=True)
    comune = fields.String(required=True)
    via = fields.String(required=True)
    area_geo = fields.String(required=True)
    tipo = fields.String(required=True)
    accessibilità = fields.String(required=True)


# Initialize the schema
hydrant_schema = HydrantSchema()


class HydrantResource(Resource):
    """
    Hydrant resource for managing hydrant data.
    This class provides methods to create, read, update, and delete hydrant records.
    """

    ENDPOINT_PATHS = [f"/{BP_NAME}/<int:id_>"]

    @jwt_required()
    def get(self, id_, identity) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Get hydrant by ID
        description: Retrieve hydrant data from the database by its integer ID.
        operationId: getHydrantById
        security:
          - bearerAuth: []
        parameters:
          - name: id_
            in: path
            required: true
            description: The unique identifier of the hydrant to retrieve.
            schema:
              type: integer
              example: 1
        responses:
          200:
            description: Hydrant found
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    id:
                      type: integer
                      example: 1
                    stato:
                      type: string
                      example: "attivo"
                    latitudine:
                      type: number
                      example: 45.4642
                    longitudine:
                      type: number
                      example: 9.19
                    comune:
                      type: string
                      example: "Milano"
                    via:
                      type: string
                      example: "Via Roma"
                    area_geo:
                      type: string
                      example: "Centro"
                    tipo:
                      type: string
                      example: "idrante"
                    accessibilità:
                      type: string
                      example: "pubblica"
          400:
            description: Invalid ID
          404:
            description: Hydrant not found
        """

        # Validate the id_
        if id_ <= 0:
            return create_response(
                message={"error": "id_ must be positive integer"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Gather the data from the database
        hydrant: Hydrant = Hydrant.query.filter_by(id=id_).first()

        # Check if the result is empty
        if hydrant is None:
            return create_response(
                message={"error": "No data found for the provided ID."},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            log_type="info",
            message=f"User {identity} fetched hydrant with id {id_}",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return the hydrant as a JSON response
        return create_response(
            message=hydrant.to_dict(), status_code=STATUS_CODES["ok"]
        )

    @jwt_required()
    def patch(self, id_, identity) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Update a hydrant by ID
        description: Update an existing hydrant record by its integer ID. Allows partial updates.
        operationId: updateHydrantById
        security:
          - bearerAuth: []
        parameters:
          - name: id_
            in: path
            required: true
            description: The unique identifier of the hydrant to update.
            schema:
              type: integer
              example: 1
        requestBody:
          required: true
          content:
            application/json:
              schema:
                type: object
                properties:
                  stato:
                    type: string
                    example: "attivo"
                  latitudine:
                    type: number
                    example: 45.4642
                  longitudine:
                    type: number
                    example: 9.19
                  comune:
                    type: string
                    example: "Milano"
                  via:
                    type: string
                    example: "Via Roma"
                  area_geo:
                    type: string
                    example: "Centro"
                  tipo:
                    type: string
                    example: "idrante"
                  accessibilità:
                    type: string
                    example: "pubblica"
        responses:
          200:
            description: Hydrant updated
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    outcome:
                      type: string
                      example: successfully updated hydrant
                    location:
                      type: string
                      example: /hydrant/1
          400:
            description: Invalid input or user not found
          404:
            description: Hydrant not found
        """

        # Allow partial updates
        try:
            data = hydrant_schema.load(request.get_json(), partial=True)
        except ValidationError as err:
            return create_response(
                message={"error": err.messages},
                status_code=STATUS_CODES["bad_request"],
            )

        # Validate the ID
        if id_ < 0:
            return create_response(
                message={"error": "id_ must be positive integer"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Gather data from the database
        hydrant = Hydrant.query.filter_by(id=id_).first()

        # Check if the hydrant exists
        if hydrant is None:
            return create_response(
                message={"error": "specified resource does not exist in the database"},
                status_code=STATUS_CODES["not_found"],
            )

        # Check if the email exists in the database
        email_exists: bool = db.session.query(
            db.session.query(User).filter_by(email=identity).exists()
        ).scalar()

        if email_exists is False:
            return create_response(
                message={"error": "email found in JWT not present in database"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Update only provided fields
        for key, value in data.items():
            setattr(hydrant, key, value)

        db.session.commit()

        # Log the action
        log(
            log_type="info",
            message=f"User {identity} updated hydrant with id {id_}",
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
        ---
        tags:
          - API Server (api_server)
        summary: Delete a hydrant by ID
        description: Delete a hydrant record from the database by its integer ID.
        operationId: deleteHydrantById
        security:
          - bearerAuth: []
        parameters:
          - name: id_
            in: path
            required: true
            description: The unique identifier of the hydrant to delete.
            schema:
              type: integer
              example: 1
        responses:
          200:
            description: Hydrant deleted
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    outcome:
                      type: string
                      example: successfully deleted hydrant
          400:
            description: Invalid ID
          404:
            description: Hydrant not found
        """

        # Validate the ID
        if id_ < 0:
            return create_response(
                message={"error": "id_ must be positive integer."},
                status_code=STATUS_CODES["bad_request"],
            )

        # Attempt to fetch and delete the hydrant in one go
        hydrant = Hydrant.query.get(id_)
        if not hydrant:
            return create_response(
                message={"error": "specified resource does not exist in the database"},
                status_code=STATUS_CODES["not_found"],
            )

        db.session.delete(hydrant)
        db.session.commit()

        # Log the action
        log(
            log_type="info",
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
        """
        ---
        tags:
          - API Server (api_server)
        summary: Get allowed HTTP methods for hydrant resource
        description: Returns the allowed HTTP methods for the hydrant resource endpoint.
        operationId: optionsHydrant
        security:
          - bearerAuth: []
        responses:
          200:
            description: Allowed methods returned
        """

        return handle_options_request(resource_class=self)


class HydrantPostResource(Resource):
    """
    Resource for creating new hydrants.
    This class provides a method to create a new hydrant record.
    """

    ENDPOINT_PATHS = [f"/{BP_NAME}"]

    @jwt_required()
    def post(self, identity) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Create a new hydrant
        description: Create a new hydrant record in the database.
        operationId: createHydrant
        security:
          - bearerAuth: []
        requestBody:
          required: true
          content:
            application/json:
              schema:
                type: object
                properties:
                  stato:
                    type: string
                    example: "attivo"
                  latitudine:
                    type: number
                    example: 45.4642
                  longitudine:
                    type: number
                    example: 9.19
                  comune:
                    type: string
                    example: "Milano"
                  via:
                    type: string
                    example: "Via Roma"
                  area_geo:
                    type: string
                    example: "Centro"
                  tipo:
                    type: string
                    example: "idrante"
                  accessibilità:
                    type: string
                    example: "pubblica"
        responses:
          201:
            description: Hydrant created
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    outcome:
                      type: string
                      example: successfully created new hydrant
                    location:
                      type: string
                      example: https://localhost:5000/api/v1/hydrant/1
          400:
            description: Invalid input or user not found
        """

        # Validate and deserialize input
        try:
            data = hydrant_schema.load(request.get_json())
        except ValidationError as err:
            return create_response(
                message={"error": err.messages},
                status_code=STATUS_CODES["bad_request"],
            )

        # Check if the email exists in the database
        email_exists: bool = db.session.query(
            db.session.query(User).filter_by(email=identity).exists()
        ).scalar()

        if email_exists is False:
            return create_response(
                message={"error": "email found in JWT not present in database"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Check if the hydrant already exists
        hydrant_exists: bool = db.session.query(
            db.func.exists().where(
                Hydrant.stato == data["stato"],
                Hydrant.latitudine == data["latitudine"],
                Hydrant.longitudine == data["longitudine"],
            )
        ).scalar()

        if hydrant_exists is True:
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
            email_ins=identity,
        )
        db.session.add(new_hydrant)
        db.session.commit()

        # Log the action
        log(
            log_type="info",
            message=f"User {identity} created hydrant with id_ {new_hydrant.id}",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return the response
        return create_response(
            message={
                "outcome": "successfully created new hydrant",
                "location": get_hateos_location_string(
                    bp_name=BP_NAME, id_=new_hydrant.id
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
        summary: Get allowed HTTP methods for hydrant resource
        description: Returns the allowed HTTP methods for the hydrant resource endpoint.
        operationId: optionsHydrantPost
        security:
          - bearerAuth: []
        responses:
          200:
            description: Allowed methods returned
        """

        return handle_options_request(resource_class=self)


# Register the resources with the API
api.add_resource(HydrantResource, *HydrantResource.ENDPOINT_PATHS)
api.add_resource(HydrantPostResource, *HydrantPostResource.ENDPOINT_PATHS)
