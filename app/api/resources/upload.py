# app/api/resources/upload.py
from flask_restful import Resource, request
from flask_jwt_extended import jwt_required
from ...services.upload_service import UploadService
from werkzeug.utils import secure_filename

class UploadPcap(Resource):
    # @jwt_required()
    def post(self):
        if 'file' not in request.files:
            return {"error": "No file provided"}, 400
        
        file = request.files['file']
        filename = secure_filename(file.filename)
        
        if not filename.lower().endswith(('.pcap', '.pcapng')):
            return {"error": "Invalid file format. Only .pcap or .pcapng allowed"}, 400
        
        try:
            service = UploadService()
            result = service.process_pcap(file, filename)
            return {
                "message": f"File {filename} processed successfully",
                "pcap_path": result["pcap_path"],
                "csv_path": result["csv_path"],
                "prediction": result["prediction"],
                "mse_threshold": result["mse_threshold"],
                # "mse_values": result["mse_values"],
                "normal_percentage": result["normal_percentage"],
                "abnormal_percentage": result["abnormal_percentage"],
                "max_mse": result["max_mse"],
                "mean_mse": result["mean_mse"]
            }, 200
        except Exception as e:
            return {"error": str(e)}, 500