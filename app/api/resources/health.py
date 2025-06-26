from flask_restful import Resource

class HealthCheck(Resource):
    def get(self):
        """Controller: Check API health & list available routes"""
        routes = {
            "status": "healthy",
            "message": "Backend API is running",
            "routes": {
                "/": "Health check & list all routes",
                "/api/model/load": "Load or reload ML model",
                "/api/predict": "Predict using loaded model",
                "/api/model/info": "Get information about the model",
                "/api/model/manage": "Model management endpoint",
                "/api/auth/register": "Register new user",
                "/api/auth/login": "Login user",
                "/api/auth/me": "Get current user info",
                "/api/auth/fullname": "Get full name of current user",
                "/api/upload/pcap": "Upload pcap file for analysis",
            }
        }
        return routes, 200
