# app/repositories/upload_repository.py
import os
import uuid
from ..config.settings import Config

class UploadRepository:
    def save_file(self, file, filename):
        upload_dir = Config.UPLOAD_DIR
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
        
        # Generate unique filename to avoid conflicts
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        file_path = os.path.join(upload_dir, unique_filename)
        
        file.save(file_path)
        return file_path