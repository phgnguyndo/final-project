# tests/test_model.py
import pytest
from app.repositories.model_repository import ModelRepository

def test_model_repository_initialization():
    try:
        repo = ModelRepository()
        assert repo.default_model_name is not None
    except FileNotFoundError:
        pytest.skip("Model file not found - skipping test")