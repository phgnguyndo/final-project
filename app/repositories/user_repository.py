# app/repositories/user_repository.py
from ..core.database import User
from .. import db
from ..utils.logger import setup_logger

class UserRepository:
    def __init__(self):
        self.logger = setup_logger()
    
    def create_user(self, username, hashed_password, full_name):
        """Repository: Create a new user"""
        try:
            user = User(username=username, password=hashed_password, full_name=full_name)
            db.session.add(user)
            db.session.commit()
            self.logger.info(f"Repository: Created user {username}")
            return user
        except Exception as e:
            db.session.rollback()
            self.logger.error(f"Repository: Failed to create user {username}: {str(e)}")
            raise
    
    def get_user_by_username(self, username):
        """Repository: Get user by username"""
        try:
            user = User.query.filter_by(username=username).first()
            return user
        except Exception as e:
            self.logger.error(f"Repository: Failed to get user {username}: {str(e)}")
            raise
    
    def get_user_by_id(self, user_id):
        """Repository: Get user by ID"""
        try:
            user = User.query.get(user_id)
            return user
        except Exception as e:
            self.logger.error(f"Repository: Failed to get user ID {user_id}: {str(e)}")
            raise