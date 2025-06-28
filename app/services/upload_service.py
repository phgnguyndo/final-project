# app/services/upload_service.py
import os
import subprocess
from ..repositories.upload_repository import UploadRepository
from ..config.settings import Config
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class UploadService:
    def __init__(self):
        self.repository = UploadRepository()

    def process_pcap(self, file, filename):
        if file.content_length > Config.MAX_UPLOAD_SIZE:
            raise ValueError("File size exceeds limit")
        
        pcap_path = self.repository.save_file(file, filename, Config.UPLOAD_DIR)
        
        csv_filename = f"{os.path.splitext(filename)[0]}.csv"
        csv_path = os.path.join(Config.CSV_OUTPUT_DIR, csv_filename)
        
        os.makedirs(Config.CSV_OUTPUT_DIR, exist_ok=True)
        
        cmd = ['cicflowmeter', '-f', pcap_path, '-c', csv_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.debug(f"CICFlowMeter stdout: {result.stdout}")
            logger.debug(f"CICFlowMeter stderr: {result.stderr}")
            if not os.path.getsize(csv_path) > 0:
                raise RuntimeError("Generated CSV file is empty. Check PCAP data or cicflowmeter version.")
        except subprocess.CalledProcessError as e:
            logger.error(f"CICFlowMeter failed: {e.stderr}")
            raise RuntimeError(f"CICFlowMeter failed: {e.stderr}")
        
        return {
            "pcap_path": pcap_path,
            "csv_path": csv_path
        }