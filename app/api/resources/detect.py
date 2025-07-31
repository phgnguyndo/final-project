from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required
from ...core.database import Detect
from ... import db
from math import ceil

class DetectResource(Resource):
    # @jwt_required()
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('page', type=int, default=1, location='args')
        parser.add_argument('per_page', type=int, default=5, location='args')
        args = parser.parse_args()

        page = args['page']
        per_page = args['per_page']

        pagination = Detect.query.order_by(Detect.timeStamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        detects = pagination.items
        total_items = pagination.total
        total_pages = ceil(total_items / per_page) if total_items > 0 and per_page > 0 else 1

        return {
            'data': [self._to_dict(d) for d in detects],
            'total': total_items,
            'pages': pagination.pages,  # giữ lại để tương thích
            'totalPages': total_pages,  # tính thủ công lại
            'current_page': page
        }, 200


    def _to_dict(self, detect):
        return {
            'id': detect.id,
            'timeStamp': detect.timeStamp.isoformat() if detect.timeStamp else None,
            'typeAttack': detect.typeAttack,
            'abNormarPercent': detect.abNormarPercent
        }