from app import create_app, socketio, realtime_service
from app.utils.logger import setup_logger

app = create_app()[0]  # Get app from create_app
logger = setup_logger()

if __name__ == '__main__':
    logger.info("Starting AI Model Backend")
    realtime_service.run()  # Run RealtimeService with socketio.run