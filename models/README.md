# models/README.md
# Models Directory
This directory stores AI model files (e.g., .pkl, .h5, .pt).
- Place your trained model files here.
- Update MODEL_NAME in .env for default model.
- Use /api/model/load to load specific models.

# README.md
# AI Model Backend

## Overview
A pure Python Flask-RESTful backend for loading and serving AI models, with user authentication (register, login, user info) using JWT and MySQL database.

## Prerequisites
- Python 3.10.17
- MySQL server (local or remote)
- Docker (optional for deployment)

## Setup
1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Setup MySQL:
   - Create a database (e.g., `ai_model_db`).
   - Update `.env` with your MySQL credentials (see `.env.example`).

3. Place your AI model in the `models/` directory and update `MODEL_NAME` in `.env` (optional).

4. Initialize database migrations:
```bash
alembic init app/migrations
alembic revision --autogenerate -m "Initial migration"
alembic upgrade head
```

5. Run the application:
```bash
python main.py
```

6. (Optional) Build and run with Docker:
```bash
docker build -t ai-model-backend .
docker run -p 5000:5000 --env-file .env ai-model-backend
```

## Project Structure
- `app/`: Core backend code
  - `api/resources/`: Controllers (API endpoints)
  - `api/middleware.py`: Placeholder for custom middleware
  - `services/`: Business logic (model and auth operations)
  - `repositories/`: Data access (model files, MySQL database)
  - `core/`: Database models
  - `utils/`: Utilities (logging, exceptions)
  - `config/`: Configuration settings
  - `migrations/`: Database migrations
- `models/`: Directory for AI model files
- `tests/`: Unit tests
- `main.py`: Application entry point

## API Endpoints
### Authentication
- `POST /api/auth/register`: Register a new user (username, password, full_name)
- `POST /api/auth/login`: Login and get JWT token
- `GET /api/auth/me`: Get current user info (requires JWT)
- `GET /api/auth/fullname`: Get current user full name (requires JWT)

### Model Operations
- `GET /api/health`: Check API health
- `POST /api/model/load`: Load a specific model (requires JWT)
- `POST /api/predict`: Make predictions (requires JWT)
- `GET /api/model/info`: Get model information (requires JWT)
- `GET /api/model/manage`: List available models (requires JWT)
- `DELETE /api/model/manage`: Unload a model (requires JWT)

## Adding New APIs
1. Create a new controller in `app/api/resources/` (e.g., `new_endpoint.py`):
```python
from flask_restful import Resource
from ...services.new_service import NewService
class NewEndpoint(Resource):
    def get(self):
        service = NewService()
        return {"data": service.get_data()}, 200
```
2. Create a service in `app/services/` (e.g., `new_service.py`):
```python
from ..repositories.new_repository import NewRepository
class NewService:
    def __init__(self):
        self.repository = NewRepository()
    def get_data(self):
        return self.repository.fetch_data()
```
3. Create a repository in `app/repositories/` (e.g., `new_repository.py`):
```python
class NewRepository:
    def fetch_data(self):
        return {"example": "data"}
```
4. Register in `app/__init__.py`:
```python
api.add_resource(NewEndpoint, '/api/new-endpoint')
```

## Authentication
- Use `Authorization: Bearer <JWT>` header for protected endpoints.
- Obtain JWT via `/api/auth/login`.

## Deployment Notes
- Copy `.env.example` to `.env` and update with your server-specific values.
- Ensure MySQL server is accessible from the application (update `MYSQL_HOST`, `MYSQL_PORT`, etc.).
- Use a secure `SECRET_KEY` and `JWT_SECRET_KEY` in production.