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
            user = self.user_repository.create_user(username, hashed_password.decode('utf-8'), full_name)
            self.logger.info(f"User registered: {username}")
            return user
        except Exception as e:
            self.logger.error(f"Registration failed: {str(e)}")
            raise
    
    def login(self, username, password):
        """Service: Authenticate user and return JWT token"""
        try:
            user = self.user_repository.get_user_by_username(username)
            if not user:
                raise ValueError("Invalid username or password")
            
            # Decode stored password from database (stored as string) to bytes
            stored_password = user.password.encode('utf-8')
            if not bcrypt.checkpw(password.encode('utf-8'), stored_password):
                raise ValueError("Invalid username or password")
            
            # Convert user.id to string for JWT identity
            token = create_access_token(identity=str(user.id))
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
            raise