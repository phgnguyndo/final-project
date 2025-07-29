# app/core/database.py
from .. import db
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PredictionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    model_name = db.Column(db.String(255), nullable=False)
    input_data = db.Column(db.JSON, nullable=False)
    prediction = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Detect(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timeStamp = db.Column(db.DateTime, nullable=False)
    typeAttack = db.Column(db.String(255), nullable=False)
    abNormarPercent = db.Column(db.Float, nullable=False) 