# app/api/resources/health.py
from flask_restful import Resource

class HealthCheck(Resource):
    def get(self):
        """Controller: Check API health"""
        return {"status": "healthy", "message": "Backend API is running"}, 200