"""
Control blueprint for managing control records in the database.
This module provides endpoints to create, read, update, and delete control records.
"""

from os.path import basename as os_path_basename
from flask import Blueprint, request, Response
from flask_restful import Api, Resource
from flask_jwt_extended import jwt_required
from typing import Dict, Union, Any
from marshmallow import fields, ValidationError
from .blueprints_utils import (
    check_authorization,
    log,
    create_response,
    get_hateos_location_string,
    handle_options_request,
)
from api_server import ma
from config import (
    STATUS_CODES,
)
from models import db, Control, Hydrant

# Define constants
BP_NAME = os_path_basename(__file__).replace("_bp.py", "")

# Create the blueprint and API
control_bp = Blueprint(BP_NAME, __name__)
api = Api(control_bp)


# Define schema
class ControlSchema(ma.Schema):
    """
    Schema for validating and serializing Control data.
    This schema defines the fields required for a control record.
    """

    id_controllo = fields.Integer(dump_only=True)  # read-only
    tipo = fields.String(required=True)
    esito = fields.Boolean(required=True)
    data = fields.Date(required=True)
    id_idrante = fields.Integer(required=True)


# Initialize the schema
control_schema = ControlSchema()


class ControlResource(Resource):
    """
    Resource for managing control records.
    This class provides methods to handle HTTP requests for control records.
    It supports GET, POST, PATCH, DELETE, and OPTIONS methods.
    """

    ENDPOINT_PATHS = [f"/{BP_NAME}/<int:id_>"]

    @jwt_required()
    def get(self, id_, identity) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Get a control row by ID
        description: Retrieve a control record from the database by its integer ID.
        operationId: getControlById
        security:
          - bearerAuth: []
        parameters:
          - name: id_
            in: path
            required: true
            description: The unique identifier of the control to retrieve.
            schema:
              type: integer
              example: 1
        responses:
          200:
            description: Control record found
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    id_controllo:
                      type: integer
                      example: 1
                    tipo:
                      type: string
                      example: "manutenzione"
                    esito:
                      type: boolean
                      example: true
                    data:
                      type: string
                      format: date
                      example: "2024-05-01"
                    id_idrante:
                      type: integer
                      example: 2
          400:
            description: Invalid ID
          404:
            description: Control not found
        """

        # Validate the ID
        if id_ <= 0:
            return create_response(
                message={"error": "control id must be positive integer."},
                status_code=STATUS_CODES["bad_request"],
            )

        # Gather the data from the database
        control: Union[Control, None] = Control.query.filter_by(
            id_controllo=id_
        ).first()

        # Check if the result is empty
        if control is None:
            return create_response(
                message={"error": "no resource found with the specified id"},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            log_type="info",
            message=f"User {identity} fetched control with id {id_}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return the control as a JSON response
        return create_response(
            message=control.to_dict(), status_code=STATUS_CODES["ok"]
        )

    @jwt_required()
    def patch(self, id_, identity) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Update a control row by ID
        description: Update an existing control record by its integer ID. Allows partial updates.
        operationId: updateControlById
        security:
          - bearerAuth: []
        parameters:
          - name: id_
            in: path
            required: true
            description: The unique identifier of the control to update.
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
                  tipo:
                    type: string
                    example: "manutenzione"
                  esito:
                    type: boolean
                    example: true
                  data:
                    type: string
                    format: date
                    example: "2024-05-01"
                  id_idrante:
                    type: integer
                    example: 2
        responses:
          200:
            description: Control updated
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    outcome:
                      type: string
                      example: successfully updated control
                    location:
                      type: string
                      example: /control/1
          400:
            description: Invalid input
          404:
            description: Control or hydrant not found
        """
        try:
            # Allow partial updates
            data = control_schema.load(request.get_json(), partial=True)
        except ValidationError as err:
            return create_response(
                message={"error": err.messages},
                status_code=STATUS_CODES["bad_request"],
            )

        # Gather data from database
        control: Control = Control.query.filter_by(id_controllo=id_).first()

        # Check that the control exists in the database
        if control is None:
            return create_response(
                message={"error": "specified control does not exist in the database"},
                status_code=STATUS_CODES["not_found"],
            )

        # Gather the data
        tipo = data.get("tipo")
        esito = data.get("esito")
        data_esecuzione = data.get("data")
        id_idrante = data.get("id_idrante")

        # Only check hydrant existence if id_idrante is being updated
        if id_idrante is not None:
            hydrant_exists = Hydrant.query.filter_by(id=id_idrante).first() is not None
            if not hydrant_exists:
                return create_response(
                    message={
                        "error": "specified hydrant does not exist in the database"
                    },
                    status_code=STATUS_CODES["not_found"],
                )

        # Update the control instance
        if tipo is not None:
            control.tipo = tipo
        if esito is not None:
            control.esito = esito
        if data_esecuzione is not None:
            control.data = data_esecuzione
        if id_idrante is not None:
            control.id_idrante = id_idrante

        # Commit the changes
        db.session.commit()

        # Log the action
        log(
            log_type="info",
            message=f"User {identity} updated control with id {id_}",
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
    def delete(self, id_, identity) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Delete a control row by ID
        description: Delete a control record from the database by its integer ID.
        operationId: deleteControlById
        security:
          - bearerAuth: []
        parameters:
          - name: id_
            in: path
            required: true
            description: The unique identifier of the control to delete.
            schema:
              type: integer
              example: 1
        responses:
          200:
            description: Control deleted
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    outcome:
                      type: string
                      example: successfully deleted control
          400:
            description: Invalid ID
          404:
            description: Control not found
        """

        # Validate the ID
        if id_ < 0:
            return create_response(
                message={"error": "id_ must be positive integer."},
                status_code=STATUS_CODES["bad_request"],
            )

        # Gather the data from the database
        control: Control = Control.query.filter_by(id_controllo=id_).first()

        # Check if the control exists
        if control is None:
            return create_response(
                message={"error": "specified resource does not exist in the database"},
                status_code=STATUS_CODES["not_found"],
            )

        # Delete the control
        db.session.delete(control)
        db.session.commit()

        # Log the action
        log(
            log_type="info",
            message=f"User {identity} deleted control with id {id_}",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return the response
        return create_response(
            message={"outcome": "successfully deleted control"},
            status_code=STATUS_CODES["ok"],
        )

    @jwt_required()
    def options(self) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Get allowed HTTP methods for control resource
        description: Returns the allowed HTTP methods for the control resource endpoint.
        operationId: optionsControl
        security:
          - bearerAuth: []
        responses:
          200:
            description: Allowed methods returned
        """

        return handle_options_request(resource_class=self)


class ControlPostResource(Resource):
    """
    Resource for creating new control records.
    This class provides a method to handle POST requests for control records.
    """

    ENDPOINT_PATHS = [f"/{BP_NAME}"]

    @jwt_required()
    def post(self, identity) -> Response:
        """
        ---
        tags:
          - API Server (api_server)
        summary: Create a new control row
        description: Create a new control record in the database.
        operationId: createControl
        security:
          - bearerAuth: []
        requestBody:
          required: true
          content:
            application/json:
              schema:
                type: object
                properties:
                  tipo:
                    type: string
                    example: "manutenzione"
                  esito:
                    type: boolean
                    example: true
                  data:
                    type: string
                    format: date
                    example: "2024-05-01"
                  id_idrante:
                    type: integer
                    example: 2
        responses:
          201:
            description: Control created
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    outcome:
                      type: string
                      example: successfully created new control
                    location:
                      type: string
                      example: https://localhost:5000/api/v1/control/1
          400:
            description: Invalid input
          404:
            description: Hydrant not found
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
        hydrant_exists: bool = db.session.query(
            db.session.query(Hydrant).filter_by(id_idrante=id_idrante).exists()
        ).scalar()

        # If the hydrant does not exist, return an error response
        if hydrant_exists is False:
            return create_response(
                message={"error": "specified hydrant does not exist in the database"},
                status_code=STATUS_CODES["not_found"],
            )

        # Create a new Control instance
        new_control = Control(
            tipo=tipo, esito=esito, data=data_esecuzione, id_idrante=id_idrante
        )

        # Add to session and commit
        db.session.add(new_control)
        db.session.commit()

        # Log the action
        log(
            log_type="info",
            message=f"User {identity} created control with id_ {new_control.id_controllo}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return the response
        return create_response(
            message={
                "outcome": "successfully created new control",
                "location": get_hateos_location_string(
                    bp_name=BP_NAME, id_=new_control.id_controllo
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
        summary: Get allowed HTTP methods for control resource
        description: Returns the allowed HTTP methods for the control resource endpoint.
        operationId: optionsControlPost
        security:
          - bearerAuth: []
        responses:
          200:
            description: Allowed methods returned
        """

        return handle_options_request(resource_class=self)


# Register the resources with the API
api.add_resource(ControlResource, *ControlResource.ENDPOINT_PATHS)
api.add_resource(ControlPostResource, *ControlPostResource.ENDPOINT_PATHS)
