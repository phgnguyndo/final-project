# app/api/resources/model.py
from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required
from ...services.model_service import ModelService
from ...utils.exceptions import APIError

class ModelLoad(Resource):
    @jwt_required()
    def post(self):
        """Controller: Load a specific AI model"""
        parser = reqparse.RequestParser()
        parser.add_argument('model_name', type=str, required=True, help="Model name is required")
        args = parser.parse_args()
        
        try:
            model_service = ModelService()
            model_service.load_model(args['model_name'])
            return {"message": f"Model {args['model_name']} loaded successfully"}, 200
        except Exception as e:
            raise APIError(f"Failed to load model: {str(e)}", status_code=500)

class ModelPredict(Resource):
    @jwt_required()
    def post(self):
        """Controller: Make prediction using loaded model"""
        parser = reqparse.RequestParser()
        parser.add_argument('data', type=dict, required=True, help="Input data is required")
        parser.add_argument('model_name', type=str, required=False, help="Optional model name")
        args = parser.parse_args()
        
        try:
            model_service = ModelService()
            prediction = model_service.predict(args['data'], args['model_name'])
            return {"prediction": prediction}, 200
        except Exception as e:
            raise APIError(f"Prediction failed: {str(e)}", status_code=500)

class ModelManage(Resource):
    @jwt_required()
    def get(self):
        """Controller: List available models"""
        try:
            model_service = ModelService()
            models = model_service.list_models()
            return {"models": models}, 200
        except Exception as e:
            raise APIError(f"Failed to list models: {str(e)}", status_code=500)
    
    @jwt_required()
    def delete(self):
        """Controller: Unload a model"""
        parser = reqparse.RequestParser()
        parser.add_argument('model_name', type=str, required=True, help="Model name is required")
        args = parser.parse_args()
        
        try:
            model_service = ModelService()
            model_service.unload_model(args['model_name'])
            return {"message": f"Model {args['model_name']} unloaded successfully"}, 200
        except Exception as e:
            raise APIError(f"Failed to unload model: {str(e)}", status_code=500)