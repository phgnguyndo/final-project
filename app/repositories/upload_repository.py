# app/repositories/upload_repository.py
import os
import uuid
from ..config.settings import Config

class UploadRepository:
    def save_file(self, file, filename, upload_dir):
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
        
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        file_path = os.path.join(upload_dir, unique_filename)
        
        file.save(file_path)
        return file_path