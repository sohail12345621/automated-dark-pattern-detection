import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    DEBUG = os.getenv("FLASK_ENV", "development") == "development"
    
    # Database settings
    DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
    DB_PORT = int(os.getenv("DB_PORT", 3306))
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_NAME = os.getenv("DB_NAME", "dark_pattern_db")

    # App directories
    BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    SCREENSHOTS_DIR = os.path.join(BASE_DIR, "screenshots")
    MODEL_DIR = os.path.join(BASE_DIR, "ml", "models")
