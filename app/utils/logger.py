# app/utils/logger.py
import logging
import os
from ..config.settings import Config

def setup_logger():
    logger = logging.getLogger('AI_Model_Backend')
    logger.setLevel(logging.INFO)
    
    os.makedirs(Config.LOGS_PATH, exist_ok=True)
    
    fh = logging.FileHandler(os.path.join(Config.LOGS_PATH, 'backend.log'))
    fh.setLevel(logging.INFO)
    
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    
    return logger