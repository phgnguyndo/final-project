from flask_restful import Resource
from ...services.realtime_service import RealtimeService

class Predict(Resource):
    def __init__(self, realtime_service):
        self.realtime_service = realtime_service

    def post(self):
        return self.realtime_service.handle_cicflowmeter_data()