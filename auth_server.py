from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from api_blueprints.blueprints_utils import log, fetchone_query, has_valid_json
from datetime import timedelta
from typing import Dict, Any, Union
from config import (AUTH_SERVER_HOST, AUTH_SERVER_PORT, 
                    AUTH_SERVER_NAME_IN_LOG, AUTH_SERVER_DEBUG_MODE, 
                    JWT_TOKEN_DURATION, JWT_SECRET_KEY,
                    STATUS_CODES)

# Initialize Flask app
app = Flask(__name__)

# Check JWT secret key length
password_bits_length = len(JWT_SECRET_KEY.encode('utf-8')) * 8
if password_bits_length < 256:
    raise RuntimeWarning("jwt secret key too short")

# Configure JWT
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY # Use a secure key (ideally at least 256 bits)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=JWT_TOKEN_DURATION)
jwt = JWTManager(app)

@app.route('/auth/login', methods=['POST'])
def login():
    """
    Login endpoint to authenticate users and generate JWT tokens.
    Expects JSON payload with 'email' and 'password' fields.
    """

    # Validate request
    data: Union[str, Dict[str, Any]] = has_valid_json(request)
    if isinstance(data, str): 
        return jsonify({'error': data}), STATUS_CODES["bad_request"]

    # Gather the request data
    email: str = data.get('email')
    password: str = data.get('password')

    # Log the attempted login operation
    log(type="info",    
        message=f"Login attempt for {email}",
        origin_name=AUTH_SERVER_NAME_IN_LOG, 
        origin_host=AUTH_SERVER_HOST, 
        origin_port=AUTH_SERVER_PORT
        )

    # Validate the request data
    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify({'error': 'email and password must be strings'}), STATUS_CODES["bad_request"]
    if not email or not password:
        return jsonify({'error': 'missing email or password'}), STATUS_CODES["bad_request"]
    if len(email) > 255 or len(password) > 255:
        return jsonify({'error': 'email or password too long'}), STATUS_CODES["bad_request"]

    try:
        # Query the database to validate the user's credentials
        user: Dict[str, Any] = fetchone_query(
                                "SELECT emailUtente, password, ruolo "
                                "FROM utenti "
                                "WHERE emailUtente = %s AND password = %s",
                                (email, password)
                                )

        if user:
            access_token: str = create_access_token(identity={'email': email,'role': user['ruolo']})

            # Log the login operation
            log(type="info",    
                message=f"User {email} logged in",
                origin_name=AUTH_SERVER_NAME_IN_LOG, 
                origin_host=AUTH_SERVER_HOST, 
                origin_port=AUTH_SERVER_PORT)

            return jsonify({'access_token': access_token}), STATUS_CODES["ok"]
        else:
            # Log the failed login attempt
            log(type="warning",    
                message=f"Failed login attempt for {email} with password {password}",
                origin_name=AUTH_SERVER_NAME_IN_LOG, 
                origin_host=AUTH_SERVER_HOST, 
                origin_port=AUTH_SERVER_PORT)
            
            # Return unauthorized status
            return jsonify({'error': 'Invalid credentials'}), STATUS_CODES["unauthorized"]
    
    except Exception as ex:
        log(type="error",    
            message=f"Error during login: {ex}",
            origin_name=AUTH_SERVER_NAME_IN_LOG, 
            origin_host=AUTH_SERVER_HOST, 
            origin_port=AUTH_SERVER_PORT)
        return jsonify({'error': 'An error occurred during login'}), STATUS_CODES["internal_error"]

@app.route('/auth/validate', methods=['POST'])
@jwt_required()
def validate():
    """
    Validate the JWT token and return the user's identity.
    """

    # Validate request
    data: Union[str, Dict[str, Any]] = has_valid_json(request)
    if isinstance(data, str): 
        return jsonify({'error': data}), STATUS_CODES["bad_request"]

    # Get the JWT identity
    identity = get_jwt_identity()

    # Validate the identity
    if not identity:
        return jsonify({'error': 'Invalid token'}), STATUS_CODES["unauthorized"]

    # Return the identity of the user
    return jsonify({'valid': True, 'identity': identity}), STATUS_CODES["ok"]

@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint to verify the server is running.
    """
    return jsonify({"status": "ok"}), STATUS_CODES["ok"]

if __name__ == '__main__':
    app.run(host=AUTH_SERVER_HOST, 
            port=AUTH_SERVER_PORT, 
            debug=AUTH_SERVER_DEBUG_MODE) # Set debug=False in production