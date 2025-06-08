# app/api/resources/info.py
from flask_restful import Resource
from flask_jwt_extended import jwt_required
from ...services.model_service import ModelService
from ...utils.exceptions import APIError

class ModelInfo(Resource):
    @jwt_required()
    def get(self):
        """Controller: Get information about loaded model"""
        parser = reqparse.RequestParser()
        parser.add_argument('model_name', type=str, required=False, help="Optional model name")
        args = parser.parse_args()
        
        try:
            model_service = ModelService()
            info = model_service.get_model_info(args['model_name'])
            return {"model_info": info}, 200
        except Exception as e:
            raise APIError(f"Failed to get model info: {str(e)}", status_code=500)