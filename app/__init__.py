from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO
from flask_cors import CORS
from .config.settings import Config
from .utils.logger import setup_logger
from .utils.exceptions import handle_api_error
from .api.resources.upload import UploadPcap
from .services.realtime_service import RealtimeService

db = SQLAlchemy()
jwt = JWTManager()
socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config['MAX_CONTENT_LENGTH'] = Config.MAX_UPLOAD_SIZE

    # Initialize CORS
    CORS(app, resources={r"/*": {"origins": ["http://localhost:3000", "http://192.168.11.132:5000"]}})

    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    socketio.init_app(app, cors_allowed_origins=["http://localhost:3000", "http://192.168.11.132:5000"], async_mode='threading')
    api = Api(app)
    
    # Setup logger
    logger = setup_logger()
    logger.info("Initializing backend application")
    
    # Register error handler
    app.errorhandler(Exception)(handle_api_error)
    
    # Initialize RealtimeService before registering resources
    realtime_service = RealtimeService(app)
    
    # Register API resources
    from .api.resources.model import ModelLoad, ModelManage
    from .api.resources.health import HealthCheck
    from .api.resources.auth import Register, Login, CurrentUser, CurrentUserFullName
    from .api.resources.predict import Predict
    
    api.add_resource(HealthCheck, '/')
    api.add_resource(ModelLoad, '/api/model/load')
    api.add_resource(ModelManage, '/api/model/manage')
    api.add_resource(Register, '/api/auth/register')
    api.add_resource(Login, '/api/auth/login')
    api.add_resource(CurrentUser, '/api/auth/me')
    api.add_resource(CurrentUserFullName, '/api/auth/fullname')
    api.add_resource(UploadPcap, '/api/upload/pcap')
    api.add_resource(Predict, '/api/predict', resource_class_kwargs={'realtime_service': realtime_service})
    
    # Initialize database
    with app.app_context():
        db.create_all()
    
    return app, socketio, realtime_service

app, socketio, realtime_service = create_app()