# app/repositories/model_repository.py
import os
import pickle
from ..config.settings import Config
from ..utils.logger import setup_logger

class ModelRepository:
    def __init__(self):
        self.models = {}  # Cache for loaded models
        self.default_model_name = Config.MODEL_NAME
        self.logger = setup_logger()
    
    def load_model(self, model_name):
        """Repository: Load AI model from file"""
        try:
            model_path = os.path.join(Config.MODEL_PATH, model_name)
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file {model_name} not found")
            
            with open(model_path, 'rb') as f:
                self.models[model_name] = pickle.load(f)
            self.logger.info(f"Repository: Loaded model {model_name} from {model_path}")
        except Exception as e:
            self.logger.error(f"Repository: Error loading model {model_name}: {str(e)}")
            raise
    
    def predict(self, input_data, model_name=None):
        """Repository: Make prediction using loaded model"""
        model_name = model_name or self.default_model_name
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not loaded")
        
        try:
            self.logger.info(f"Repository: Making prediction with {model_name}")
            # Replace with actual prediction logic
            return {"result": f"Prediction from {model_name}"}
        except Exception as e:
            self.logger.error(f"Repository: Prediction error for {model_name}: {str(e)}")
            raise
    
    def get_model_info(self, model_name=None):
        """Repository: Return information about the loaded model"""
        model_name = model_name or self.default_model_name
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not loaded")
        
        return {
            "model_name": model_name,
            "model_type": "SampleModel",
            "version": "1.0.0",
            "path": os.path.join(Config.MODEL_PATH, model_name)
        }
    
    def list_models(self):
        """Repository: List all available model files"""
        try:
            models = [f for f in os.listdir(Config.MODEL_PATH) if f.endswith(('.pkl', '.h5', '.pt'))]
            return models
        except Exception as e:
            self.logger.error(f"Repository: Error listing models: {str(e)}")
            raise
    
    def unload_model(self, model_name):
        """Repository: Unload a model from memory"""
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not loaded")
        
        del self.models[model_name]
        self.logger.info(f"Repository: Unloaded model {model_name}")
