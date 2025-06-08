# app/api/resources/auth.py
from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity
from ...services.auth_service import AuthService
from ...utils.exceptions import APIError

class Register(Resource):
    def post(self):
        """Controller: Register a new user"""
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help="Username is required")
        parser.add_argument('password', type=str, required=True, help="Password is required")
        parser.add_argument('full_name', type=str, required=True, help="Full name is required")
        args = parser.parse_args()
        
        try:
            auth_service = AuthService()
            user = auth_service.register(args['username'], args['password'], args['full_name'])
            return {"message": "User registered successfully", "user_id": user.id}, 201
        except Exception as e:
            raise APIError(f"Registration failed: {str(e)}", status_code=400)

class Login(Resource):
    def post(self):
        """Controller: Login and return JWT token"""
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help="Username is required")
        parser.add_argument('password', type=str, required=True, help="Password is required")
        args = parser.parse_args()
        
        try:
            auth_service = AuthService()
            token = auth_service.login(args['username'], args['password'])
            return {"access_token": token}, 200
        except Exception as e:
            raise APIError(f"Login failed: {str(e)}", status_code=401)

class CurrentUser(Resource):
    @jwt_required()
    def get(self):
        """Controller: Get current user info"""
        try:
            user_id = get_jwt_identity()
            auth_service = AuthService()
            user = auth_service.get_user_by_id(user_id)
            return {
                "user_id": user.id,
                "username": user.username,
                "full_name": user.full_name
            }, 200
        except Exception as e:
            raise APIError(f"Failed to get user info: {str(e)}", status_code=400)

class CurrentUserFullName(Resource):
    @jwt_required()
    def get(self):
        """Controller: Get current user full name"""
        try:
            user_id = get_jwt_identity()
            auth_service = AuthService()
            user = auth_service.get_user_by_id(user_id)
            return {"full_name": user.full_name}, 200
        except Exception as e:
            raise APIError(f"Failed to get full name: {str(e)}", status_code=400)