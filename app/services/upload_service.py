# app/services/upload_service.py
import os
import subprocess
from ..repositories.upload_repository import UploadRepository
from ..config.settings import Config

class UploadService:
    def __init__(self):
        self.repository = UploadRepository()

    def process_pcap(self, file, filename):
        if file.content_length > Config.MAX_UPLOAD_SIZE:
            raise ValueError("File size exceeds limit")
        
        pcap_path = self.repository.save_file(file, filename, Config.UPLOAD_DIR)
        
        csv_filename = f"{os.path.splitext(filename)[0]}.csv"
        csv_path = os.path.join(Config.CSV_OUTPUT_DIR, csv_filename)
        
        # Gọi cicflowmeter CLI với cú pháp đúng
        cmd = ['cicflowmeter', '-f', pcap_path, '-c', csv_path]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if result.returncode != 0:
            raise RuntimeError(f"CICFlowMeter failed: {result.stderr}")
        
        return {
            "pcap_path": pcap_path,
            "csv_path": csv_path
        }