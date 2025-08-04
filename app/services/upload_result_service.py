from ..repositories.upload_result_repository import UploadResultRepository

class UploadResultService:
    def __init__(self):
        self.repository = UploadResultRepository()

    def get_all_results(self, page=1, per_page=5):
        results, total_items, total_pages, pages = self.repository.get_all_results(page, per_page)
        return {
            'data': [{
                'id': result.id,
                'filename': result.filename,
                'normal_percent': result.normal_percent,
                'abnormal_percent': result.abnormal_percent,
                'predict': result.predict,
                'created_at': result.created_at.isoformat() if result.created_at else None
            } for result in results],
            'total': total_items,
            'pages': pages,
            'totalPages': total_pages,
            'current_page': page
        }

    def get_result_by_id(self, result_id):
        result = self.repository.get_result_by_id(result_id)
        if not result:
            return None
        return {
            'id': result.id,
            'filename': result.filename,
            'normal_percent': result.normal_percent,
            'abnormal_percent': result.abnormal_percent,
            'predict': result.predict,
            'created_at': result.created_at.isoformat() if result.created_at else None
        }