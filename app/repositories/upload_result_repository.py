from ..core.database import db
from ..core.database import UploadResult
from math import ceil

class UploadResultRepository:
    def get_all_results(self, page=1, per_page=5):
        pagination = UploadResult.query.order_by(UploadResult.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        results = pagination.items
        total_items = pagination.total
        total_pages = ceil(total_items / per_page) if total_items > 0 and per_page > 0 else 1
        return results, total_items, total_pages, pagination.pages

    def get_result_by_id(self, result_id):
        return UploadResult.query.get(result_id)