# app/services/model_service.py
from ..repositories.model_repository import ModelRepository
from ..utils.logger import setup_logger
from ..core.database import PredictionLog
from .. import db

class ModelService:
    def __init__(self):
        self.repository = ModelRepository()
        self.logger = setup_logger()
    
    def load_model(self, model_name):
        """Service: Load a model via repository"""
        try:
            self.repository.load_model(model_name)
            self.logger.info(f"Service: Loaded model {model_name}")
        except Exception as e:
            self.logger.error(f"Service: Failed to load model {model_name}: {str(e)}")
            raise
    
    def predict(self, input_data, model_name=None):
        """Service: Make prediction and log to database"""
        try:
            prediction = self.repository.predict(input_data, model_name)
            self.logger.info(f"Service: Prediction made with model {model_name or 'default'}")
            
            # Log prediction to database
            log = PredictionLog(
                model_name=model_name or self.repository.default_model_name,
                input_data=input_data,
                prediction=prediction
            )
            db.session.add(log)
            db.session.commit()
            
            return prediction
        except Exception as e:
            self.logger.error(f"Service: Prediction failed: {str(e)}")
            raise
    
    def get_model_info(self, model_name=None):
        """Service: Get model information"""
        try:
            info = self.repository.get_model_info(model_name)
            self.logger.info(f"Service: Retrieved info for model {model_name or 'default'}")
            return info
        except Exception as e:
            self.logger.error(f"Service: Failed to get model info: {str(e)}")
            raise
    
    def list_models(self):
        """Service: List available models"""
        try:
            models = self.repository.list_models()
            self.logger.info("Service: Listed available models")
            return models
        except Exception as e:
            self.logger.error(f"Service: Failed to list models: {str(e)}")
            raise
    
    def unload_model(self, model_name):
        """Service: Unload a model"""
        try:
            self.repository.unload_model(model_name)
            self.logger.info(f"Service: Unloaded model {model_name}")
        except Exception as e:
            self.logger.error(f"Service: Failed to unload model {model_name}: {str(e)}")
            raise