# app/utils/exceptions.py
from flask_restful import abort

class APIError(Exception):
    def __init__(self, message, status_code=400):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)
    
    def to_dict(self):
        return {"error": self.message}

def handle_api_error(error):
    response = {"error": str(error)} if not hasattr(error, 'to_dict') else error.to_dict()
    status_code = getattr(error, 'status_code', 500)
    return response, status_code