from os.path import basename as os_path_basename
from flask import Blueprint, request, Response
from flask_restful import Api, Resource
from flask_jwt_extended import get_jwt_identity
from typing import Dict, Union, Any
from blueprints_utils import (check_authorization, build_select_query_from_filters,
                               fetchone_query, fetchall_query, 
                               execute_query, log, 
                               jwt_required_endpoint, create_response, 
                               build_update_query_from_filters, has_valid_json,
                               is_input_safe, get_class_http_verbs)
from config import (API_SERVER_HOST, API_SERVER_PORT, 
                    API_SERVER_NAME_IN_LOG, STATUS_CODES)

# Define constants
BP_NAME = os_path_basename(__file__).replace('_bp.py', '')

# Create the blueprint and API
hydrant_bp = Blueprint(BP_NAME, __name__)
api = Api(hydrant_bp)

class Hydrant(Resource):
    @jwt_required_endpoint
    def get(self) -> Response:
        ...

    @jwt_required_endpoint
    def post(self) -> Response:
        ...
    
    @jwt_required_endpoint
    def patch(self) -> Response:
        ...
    
    @jwt_required_endpoint
    def put(self) -> Response:
        ...

    @jwt_required_endpoint
    def delete(self) -> Response:
        ...
     
    @jwt_required_endpoint
    def options(self) -> Response:
        # Define allowed methods
        allowed_methods = get_class_http_verbs(type(self))
        
        # Create the response
        response = Response()
        response.headers['Allow'] = ', '.join(allowed_methods)
        response.headers['Access-Control-Allow-Origin'] = '*'  # Adjust as needed for CORS
        response.headers['Access-Control-Allow-Methods'] = ', '.join(allowed_methods)
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        
        return response