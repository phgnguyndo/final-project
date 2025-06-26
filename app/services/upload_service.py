# app/services/upload_service.py
import os
from ..repositories.upload_repository import UploadRepository
from ..config.settings import Config

class UploadService:
    def __init__(self):
        self.repository = UploadRepository()

    def save_pcap(self, file, filename):
        if file.content_length > Config.MAX_UPLOAD_SIZE:
            raise ValueError("File size exceeds limit")
        return self.repository.save_file(file, filename)