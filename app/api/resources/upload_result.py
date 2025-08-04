from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required
from ...services.upload_result_service import UploadResultService

class UploadResult(Resource):
    # @jwt_required()
    def get(self, result_id=None):
        service = UploadResultService()
        if result_id:
            result = service.get_result_by_id(result_id)
            if not result:
                return {"message": "Result not found"}, 404
            return {"data": result}, 200
        
        parser = reqparse.RequestParser()
        parser.add_argument('page', type=int, default=1, location='args')
        parser.add_argument('per_page', type=int, default=5, location='args')
        args = parser.parse_args()

        results = service.get_all_results(args['page'], args['per_page'])
        return results, 200