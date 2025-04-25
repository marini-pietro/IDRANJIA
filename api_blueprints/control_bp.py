from os.path import basename as os_path_basename
from flask import Blueprint, request, Response
from flask_restful import Api, Resource
from flask_jwt_extended import get_jwt_identity
from typing import Dict, Union, Any
from blueprints_utils import (check_authorization, fetchone_query, 
                              execute_query, log, 
                              jwt_required_endpoint, create_response, 
                              has_valid_json, is_input_safe, 
                              get_class_http_verbs, parse_date_string)
from config import (API_SERVER_HOST, API_SERVER_PORT, 
                    API_SERVER_NAME_IN_LOG, STATUS_CODES)

# Define constants
BP_NAME = os_path_basename(__file__).replace('_bp.py', '')

# Create the blueprint and API
control_bp = Blueprint(BP_NAME, __name__)
api = Api(control_bp)

class Control(Resource):

    ENDPOINT_PATHS = [f'/{BP_NAME}', f'/{BP_NAME}/<int:id>']

    @jwt_required_endpoint
    def get(self, id) -> Response:
        """
        Get a control row data by ID.
        ID is passed as a path variable integer.
        """

        # Validate the ID
        if not isinstance(id, int) or id <= 0:
            return create_response(STATUS_CODES['BAD_REQUEST'], 'Invalid ID provided.')

        # Get the data
        control = fetchone_query("SELECT tipo, esito, data, idI FROM controlli WHERE id = %s", (id, ))

        # Check if the result is empty
        if not control:
            return create_response(message={"error": "No data found for the provided ID."}, status_code=STATUS_CODES['not_found'])

        # Log the action
        log(type='info',
            message=f'User {get_jwt_identity().get("email")} fetched control with id {id}',
            origin_name=API_SERVER_NAME_IN_LOG, 
            origin_host=API_SERVER_HOST, 
            origin_port=API_SERVER_PORT,
            structured_data=f"[{Control.ENDPOINT_PATHS[0]} Verb GET]")

        # Return the control as a JSON response
        return create_response(message=control, status_code=STATUS_CODES['ok'])

    @jwt_required_endpoint
    def post(self) -> Response:
        """
        Create a new row in control table.
        The data is passed as a JSON body.
        """

        # Validate request
        data: Union[str, Dict[str, Any]] = has_valid_json(request)
        if isinstance(data, str):
            return create_response(message={'error': data}, status_code=STATUS_CODES["bad_request"])
        
        # Check for sql injection
        if not is_input_safe(data):
            return create_response(message={'error': 'invalid input, suspected sql injection'}, status_code=STATUS_CODES["bad_request"])
        
        # Gather the data
        tipo = data.get('tipo')
        esito = data.get('esito')
        data = data.get('data')
        idI = data.get('idI')

        # Validate the data
        if not all([tipo, esito, data, idI]):
            return create_response(message={'error': 'missing required fields.'}, status_code=STATUS_CODES["bad_request"])
        if not isinstance(esito, bool):
            return create_response(message={'error': 'esito must be boolean value'}, status_code=STATUS_CODES["bad_request"])
        if not isinstance(tipo, str):
            return create_response(message={'error': 'tipo must be string value'}, status_code=STATUS_CODES["bad_request"])
        if not isinstance(data, str):
            return create_response(message={'error': 'data must be string value'}, status_code=STATUS_CODES["bad_request"])
        if not (isinstance(idI, int) and idI >= 0 or isinstance(idI, str) and idI.isdigit()):
            return create_response(message={'error': 'idI must be a positive integer or a numeric string'}, status_code=STATUS_CODES["bad_request"])
        
        # Perform casting if needed
        if isinstance(idI, str):
            idI = int(idI)
        data = parse_date_string(data)

        # Check that the idI exists in the database
        idI_exists = fetchone_query("SELECT stato FROM idranti WHERE id = %s", (idI, )) # Column in SELECT is not important, we just need to check if the id exists
        if not idI_exists:
            return create_response(message={'error': 'idI does not exist in the database'}, status_code=STATUS_CODES["not_found"])
        
        # Execute the query
        lastrowid = execute_query("INSERT INTO controlli (tipo, esito, data, idI) VALUES (%s, %s, %s, %s)", (tipo, esito, data, idI))
        
        # Log the action
        log(type='info', 
            message=f'User {get_jwt_identity().get("email")} created control with id {lastrowid}',
            origin_name=API_SERVER_NAME_IN_LOG, 
            origin_host=API_SERVER_HOST, 
            origin_port=API_SERVER_PORT,
            structured_data=f"[{Control.ENDPOINT_PATHS[0]} Verb POST]")
        
        # Return the response
        return create_response(message={'outcome': "successfully created new control",
                                        'location': f"http://{API_SERVER_HOST}:{API_SERVER_PORT}/{Control.ENDPOINT_PATHS[0]}/{lastrowid}"}, status_code=STATUS_CODES['created'])
    
    @jwt_required_endpoint
    def patch(self, id) -> Response:
        ...
    
    @jwt_required_endpoint
    def delete(self, id) -> Response:
        """
        Delete a control row by ID.
        ID is passed as a path variable integer.
        """

        # Validate the ID
        if not isinstance(id, int) or id < 0:
            return create_response(message={'error': 'id must be positive integer.'}, status_code=STATUS_CODES['bad_request'])
        
        # Check if the ID exists in the database
        control = fetchone_query("SELECT esito FROM controlli WHERE idC = %s", (id, )) # Column in SELECT is not important, we just need to check if the id exists
        if not control:
            return create_response(message={'error': 'id does not exist in the database'}, status_code=STATUS_CODES['not_found'])
        
        # Execute the query
        execute_query("DELETE FROM controlli WHERE idC = %s", (id, ))

        # Log the action
        log(type='info', 
            message=f'User {get_jwt_identity().get("email")} deleted control with id {id}',
            origin_name=API_SERVER_NAME_IN_LOG, 
            origin_host=API_SERVER_HOST, 
            origin_port=API_SERVER_PORT,
            structured_data=f"[{Control.ENDPOINT_PATHS[1]} Verb DELETE]")
        
        # Return the response
        return create_response(message={'outcome': "successfully deleted control"}, status_code=STATUS_CODES['ok'])
     
    @jwt_required_endpoint
    def options(self) -> Response:
        # Define allowed methods
        allowed_methods = get_class_http_verbs(type(self))
        
        # Create the response
        response = Response(status=STATUS_CODES["ok"])
        response.headers['Allow'] = ', '.join(allowed_methods)
        response.headers['Access-Control-Allow-Origin'] = '*'  # Adjust as needed for CORS
        response.headers['Access-Control-Allow-Methods'] = ', '.join(allowed_methods)
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        
        return response
    
api.add_resource(Control, *Control.ENDPOINT_PATHS)