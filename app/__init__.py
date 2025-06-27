from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from .config.settings import Config
from .utils.logger import setup_logger
from .utils.exceptions import handle_api_error
from .api.resources.upload import UploadPcap

db = SQLAlchemy()
jwt = JWTManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config['MAX_CONTENT_LENGTH'] = Config.MAX_UPLOAD_SIZE
    
    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    api = Api(app)
    
    # Setup logger
    logger = setup_logger()
    logger.info("Initializing backend application")
    
    # Register error handler
    app.errorhandler(Exception)(handle_api_error)
    
    # Register API resources (Controllers)
    from .api.resources.model import ModelLoad, ModelPredict, ModelManage
    from .api.resources.health import HealthCheck
    from .api.resources.info import ModelInfo
    from .api.resources.auth import Register, Login, CurrentUser, CurrentUserFullName
    
    api.add_resource(HealthCheck, '/')
    api.add_resource(ModelLoad, '/api/model/load')
    api.add_resource(ModelPredict, '/api/predict')
    api.add_resource(ModelInfo, '/api/model/info')
    api.add_resource(ModelManage, '/api/model/manage')
    api.add_resource(Register, '/api/auth/register')
    api.add_resource(Login, '/api/auth/login')
    api.add_resource(CurrentUser, '/api/auth/me')
    api.add_resource(CurrentUserFullName, '/api/auth/fullname')
    api.add_resource(UploadPcap, '/api/upload/pcap')
    
    # Initialize database
    with app.app_context():
        db.create_all()
    
    return app