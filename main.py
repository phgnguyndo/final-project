# main.py
from app import create_app
from app.utils.logger import setup_logger

app = create_app()
logger = setup_logger()

if __name__ == '__main__':
    logger.info("Starting AI Model Backend")
    app.run(host='0.0.0.0', port=5000, debug=app.config['DEBUG'])