import os
from datetime import timedelta
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

class Config:
    """Configuration de base pour l'application"""
    
    # Base de données
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///mental_wellbeing.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Sécurité
    SECRET_KEY = os.getenv('SECRET_KEY')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    
    # Vérification des clés en production
    if os.getenv('FLASK_ENV') == 'production':
        if not SECRET_KEY or not JWT_SECRET_KEY:
            raise ValueError("SECRET_KEY et JWT_SECRET_KEY sont obligatoires en production!")
    
    # JWT Configuration
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        seconds=int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600))
    )
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(
        seconds=int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES', 2592000))
    )
    
    # Bcrypt
    BCRYPT_LOG_ROUNDS = int(os.getenv('BCRYPT_LOG_ROUNDS', 12))
    
    # Debug
    DEBUG = os.getenv('FLASK_ENV') == 'development'