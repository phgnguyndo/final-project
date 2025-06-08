# app/api/middleware.py
# Placeholder for custom middleware if needed
from flask_restful import Resource
from ..utils.exceptions import APIError

def custom_middleware():
    pass

# app/services/auth_service.py
from flask_jwt_extended import create_access_token
from ..repositories.user_repository import UserRepository
from ..utils.logger import setup_logger
import bcrypt

class AuthService:
    def __init__(self):
        self.user_repository = UserRepository()
        self.logger = setup_logger()
    
    def register(self, username, password, full_name):
        """Service: Register a new user"""
        try:
            if self.user_repository.get_user_by_username(username):
                raise ValueError("Username already exists")
            
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            user = self.user_repository.create_user(username, hashed_password, full_name)
            self.logger.info(f"User registered: {username}")
            return user
        except Exception as e:
            self.logger.error(f"Registration failed: {str(e)}")
            raise
    
    def login(self, username, password):
        """Service: Authenticate user and return JWT token"""
        try:
            user = self.user_repository.get_user_by_username(username)
            if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password):
                raise ValueError("Invalid username or password")
            
            token = create_access_token(identity=user.id)
            self.logger.info(f"User logged in: {username}")
            return token
        except Exception as e:
            self.logger.error(f"Login failed: {str(e)}")
            raise
    
    def get_user_by_id(self, user_id):
        """Service: Get user by ID"""
        try:
            user = self.user_repository.get_user_by_id(user_id)
            if not user:
                raise ValueError("User not found")
            self.logger.info(f"Retrieved user info for ID: {user_id}")
            return user
        except Exception as e:
            self.logger.error(f"Failed to get user info: {str(e)}")