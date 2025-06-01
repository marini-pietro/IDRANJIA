from os.path import basename as os_path_basename
from flask import Blueprint, request, Response
from flask_restful import Api, Resource
from flask_jwt_extended import jwt_required
from typing import Dict, Union, Any
from flask_marshmallow import Marshmallow
from marshmallow import fields, ValidationError
import re
from .blueprints_utils import (
    check_authorization,
    log,
    create_response,
    get_hateos_location_string,
    handle_options_request,
)
from config import (
    STATUS_CODES,
)
from models import db, Operator

# Define constants
BP_NAME = os_path_basename(__file__).replace("_bp.py", "")

# Create the blueprint and API
operator_bp = Blueprint(BP_NAME, __name__)
api = Api(operator_bp)

# Initialize Marshmallow
ma = Marshmallow()

# Define schemas
class OperatorSchema(ma.Schema):
    CF = fields.String(required=True)
    nome = fields.String(required=True)
    cognome = fields.String(required=True)

operator_schema = OperatorSchema()


class OperatorResource(Resource):

    ENDPOINT_PATHS = [f"/{BP_NAME}", f"/{BP_NAME}/<int:id_>", f"/{BP_NAME}/<string:CF>"]

    @jwt_required()
    def get(self, id_, identity) -> Response:
        """
        Get the information of an operator from the database.
        """

        # Validate the id_
        if id_ < 0:
            return create_response(
                message={"error": "id must be a positive integer"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Get the data
        operator: Operator = Operator.query.filter_by(id=id_).first()

        # Check if the result is empty
        if operator is None:
            return create_response(
                message={"error": "no resource found with specified id"},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            type="info",
            message=f"User {identity} fetched operator with id {id_}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return the operator as a JSON response
        return create_response(message=operator_schema.dump(operator), 
                               status_code=STATUS_CODES["ok"])

    @jwt_required()
    def post(self, identity) -> Response:
        """
        Create a new operator row in the database.
        """
        try:
            # Validate and deserialize input
            data = operator_schema.load(request.get_json())
        except ValidationError as err:
            return create_response(
                message={"error": err.messages},
                status_code=STATUS_CODES["bad_request"],
            )

        cf = data["CF"]
        name = data["nome"]
        surname = data["cognome"]

        # Check if the operator already exists
        operator_exists: Operator = Operator.query.filter_by(CF=cf).first()
        if operator_exists:
            return create_response(
            message={"error": "operator already exists."},
            status_code=STATUS_CODES["bad_request"],
            )

        # Create a new operator instance
        new_operator = Operator(CF=cf, nome=name, cognome=surname)

        # Add and commit the new operator to the database
        db.session.add(new_operator)
        db.session.commit()

        # Log the action
        log(
            type="info",
            message=f"User {identity} created operator with id {new_operator.id}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Return the new operator as a JSON response
        return create_response(
            message={
                "outcome": "operator successfully created",
                "location": get_hateos_location_string(bp_name=BP_NAME, id_=new_operator.id),
            },
            status_code=STATUS_CODES["created"],
        )

    @jwt_required()
    def patch(self, id_, identity) -> Response:
        """
        Update an operator in the database by its ID.
        """
        try:
            # Validate and deserialize input
            data = operator_schema.load(request.get_json())
        except ValidationError as err:
            return create_response(
                message={"error": err.messages},
                status_code=STATUS_CODES["bad_request"],
            )

        cf = data.get("CF")
        nome = data.get("nome")
        cognome = data.get("cognome")

        # Validate the id
        if id_ < 0:
            return create_response(
                message={"error": "id must be a positive integer"},
                status_code=STATUS_CODES["bad_request"],
            )

        # Check that the operator exists
        operator: Operator = Operator.query.filter_by(id=id_).first()
        if operator is None:
            return create_response(
            message={"error": "no resource found with specified id"},
            status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            type="info",
            message=f"User {identity} updated operator with id {id_}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Update the operator's attributes
        operator.CF = cf or operator.CF
        operator.nome = nome or operator.nome
        operator.cognome = cognome or operator.cognome

        # Commit the changes to the database
        db.session.commit()

        # Return the response
        return create_response(
            message={
                "outcome": "successfully updated operator",
                "location": get_hateos_location_string(bp_name=BP_NAME, id_=id_),
            },
            status_code=STATUS_CODES["ok"],
        )

    @jwt_required()
    def delete(self, CF, identity) -> Response:
        """
        Delete an operator from the database.
        """

        # Validate the CF
        if not isinstance(CF, str) or not re.match(r"^[A-Z0-9]{16}$", CF):
            return create_response(
            message={"error": "CF must be a 16-character alphanumeric string."},
            status_code=STATUS_CODES["bad_request"],
            )

        # Check if the operator exists
        operator: Operator = Operator.query.filter_by(CF=CF).first()
        if operator is None:
            return create_response(
                message={"error": "no resource found with specified cf"},
                status_code=STATUS_CODES["not_found"],
            )

        # Log the action
        log(
            type="info",
            message=f"User {identity} deleted operator with cf {CF}",
            message_id="UserAction",
            structured_data=f"[endpoint='{request.path} verb='{request.method}']",
        )

        # Delete the operator
        db.session.delete(operator)
        db.session.commit()

        # Return the response
        return create_response(
            message={"outcome": "successfully deleted operator"},
            status_code=STATUS_CODES["ok"],
        )

    @jwt_required()
    def options(self) -> Response:
        """
        Handle OPTIONS requests for CORS preflight checks.
        This method returns the allowed HTTP methods for the endpoint.
        """
        return handle_options_request(resource_class=self)


api.add_resource(OperatorResource, *OperatorResource.ENDPOINT_PATHS)
