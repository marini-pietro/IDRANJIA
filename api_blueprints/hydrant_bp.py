from os.path import basename as os_path_basename
from flask import Blueprint, request, Response
from flask_restful import Api, Resource
from flask_jwt_extended import get_jwt_identity
from typing import Dict, Union, Any
from blueprints_utils import (check_authorization, fetchone_query, 
                              execute_query, log, 
                              jwt_required_endpoint, create_response, 
                              has_valid_json, is_input_safe, 
                              get_class_http_verbs)
from config import (API_SERVER_HOST, API_SERVER_PORT, 
                    API_SERVER_NAME_IN_LOG, STATUS_CODES)

# Define constants
BP_NAME = os_path_basename(__file__).replace('_bp.py', '')

# Create the blueprint and API
hydrant_bp = Blueprint(BP_NAME, __name__)
api = Api(hydrant_bp)

class Hydrant(Resource):

    ENDPOINT_PATHS = [f'/{BP_NAME}', f'/{BP_NAME}/<int:id>']

    @jwt_required_endpoint
    def get(self, id) -> Response:
        """
        Read hydrant data from the database.
        """

        # Validate the id
        if not isinstance(id, int) or id <= 0:
            return create_response(message={"error": "id must be positive integer"}, status_code=STATUS_CODES["bad_request"])
        
        # Get the data
        hydrant = fetchone_query("SELECT stato, latitudine, longitudine, comune, via, areaGeo, tipo, accessibilità, emailIns FROM idranti WHERE id = %s", (id,))

        # Check if the result is empty
        if not hydrant:
            return create_response(message={"error": "No data found for the provided ID."}, status_code=STATUS_CODES["not_found"])
        
        # Log the action
        log(type='info',
            message=f'User {get_jwt_identity().get("email")} fetched hydrant with id {id}',
            origin_name=API_SERVER_NAME_IN_LOG, 
            origin_host=API_SERVER_HOST, 
            origin_port=API_SERVER_PORT,
            structured_data=f"[{Hydrant.ENDPOINT_PATHS[0]} Verb GET]")
        
        # Return the hydrant as a JSON response
        return create_response(message=hydrant, status_code=STATUS_CODES["ok"])

    @jwt_required_endpoint
    def post(self) -> Response:
        """
        Create a new hydrant row in the database.
        """

        # Validate request
        data: Union[str, Dict[str, Any]] = has_valid_json(request)
        if isinstance(data, str):
            return create_response(message={'error': data}, status_code=STATUS_CODES["bad_request"])
        
        # Check for sql injection
        if not is_input_safe(data):
            return create_response(message={'error': 'invalid input, suspected sql injection'}, status_code=STATUS_CODES["bad_request"])
        
        # Gather the data
        stato = data.get('stato')
        latitudine = data.get('latitudine')
        longitudine = data.get('longitudine')
        comune = data.get('comune')
        via = data.get('via')
        areaGeo = data.get('areaGeo')
        tipo = data.get('tipo')
        accessibilità = data.get('accessibilità')
        emailIns = get_jwt_identity().get("email")

        # Validate the data
        if not all([stato, latitudine, longitudine, comune, via, areaGeo, tipo, accessibilità]):
            return create_response(message={'error': 'missing required fields.'}, status_code=STATUS_CODES["bad_request"])
        if not isinstance(stato, str):
            return create_response(message={'error': 'stato must be string'}, status_code=STATUS_CODES["bad_request"])
        if not isinstance(latitudine, float):
            return create_response(message={'error': 'latitudine must be float'}, status_code=STATUS_CODES["bad_request"])
        if not isinstance(longitudine, float):
            return create_response(message={'error': 'longitudine must be float'}, status_code=STATUS_CODES["bad_request"])
        if not isinstance(comune, str):
            return create_response(message={'error': 'comune must be string'}, status_code=STATUS_CODES["bad_request"])
        if not isinstance(via, str):
            return create_response(message={'error': 'via must be string'}, status_code=STATUS_CODES["bad_request"])
        if not isinstance(areaGeo, str):
            return create_response(message={'error': 'areaGeo must be string'}, status_code=STATUS_CODES["bad_request"])
        if not isinstance(tipo, str):
            return create_response(message={'error': 'tipo must be string'}, status_code=STATUS_CODES["bad_request"])
        if not isinstance(accessibilità, str):
            return create_response(message={'error': 'accessibilità must be string'}, status_code=STATUS_CODES["bad_request"])
        
        # Check if the email exists in the database
        email_exists = fetchone_query("SELECT email FROM utenti WHERE email = %s", (emailIns,))
        if not email_exists:
            return create_response(message={'error': 'email found in JWT not present in database'}, status_code=STATUS_CODES["bad_request"])
        
        # Check if the hydrant already exists
        hydrant_exists = fetchone_query("SELECT areaGeo FROM idranti WHERE stato = %s AND latitudine = %s AND longitudine = %s", (stato, latitudine, longitudine))
        if hydrant_exists:
            return create_response(message={'error': 'hydrant with provided stato, latitudine and longitudine already exists'}, status_code=STATUS_CODES["bad_request"])
        
        # Insert the new hydrant into the database
        insert_query = "INSERT INTO idranti (stato, latitudine, longitudine, comune, via, areaGeo, tipo, accessibilità, emailIns) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
        lastrowid = execute_query(insert_query, (stato, latitudine, longitudine, comune, via, areaGeo, tipo, accessibilità, emailIns))

        # Log the action
        log(type='info',
            message=f'User {get_jwt_identity().get("email")} created hydrant with id {lastrowid}',
            origin_name=API_SERVER_NAME_IN_LOG, 
            origin_host=API_SERVER_HOST, 
            origin_port=API_SERVER_PORT,
            structured_data=f"[{Hydrant.ENDPOINT_PATHS[0]} Verb POST]")
        
        # Return the response
        return create_response(message={'outcome': "successfully created new hydrant",
                                        'location': f"http://{API_SERVER_HOST}:{API_SERVER_PORT}/{Hydrant.ENDPOINT_PATHS[0]}/{lastrowid}"}, status_code=STATUS_CODES['created'])

    @jwt_required_endpoint
    def patch(self) -> Response:
        ...
    
    @jwt_required_endpoint
    def delete(self, id) -> Response:
        """
        Delete a hydrant row by ID.
        ID is passed as a path variable integer.
        """

        # Validate the ID
        if not isinstance(id, int) or id < 0:
            return create_response(message={'error': 'id must be positive integer.'}, status_code=STATUS_CODES['bad_request'])
        
        # Check if the ID exists in the database
        hydrant = fetchone_query("SELECT stato FROM idranti WHERE id = %s", (id,)) # Column in SELECT is not important, we just need to check if the id exists
        if hydrant:
            return create_response(message={'error': 'id already exist in the database'}, status_code=STATUS_CODES['not_found'])
        
        # Execute the query
        execute_query("DELETE FROM idranti WHERE id = %s", (id,))

        # Log the action
        log(type='info',
            message=f'User {get_jwt_identity().get("email")} deleted hydrant with id {id}',
            origin_name=API_SERVER_NAME_IN_LOG, 
            origin_host=API_SERVER_HOST, 
            origin_port=API_SERVER_PORT,
            structured_data=f"[{Hydrant.ENDPOINT_PATHS[1]} Verb DELETE]")
        
        # Return the response
        return create_response(message={'outcome': "successfully deleted hydrant"}, status_code=STATUS_CODES['ok'])
     
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
    
api.add_resource(Hydrant, *Hydrant.ENDPOINT_PATHS)