import os
from dotenv import load_dotenv
from typing import List

# Charge le fichier .env à la racine du projet
load_dotenv()

class Settings:
    def __init__(self):
        self.APP_NAME: str = os.getenv("APP_NAME")
        self.APP_ENV: str = os.getenv("APP_ENV")

        # DB obligatoire → plante si manquant
        self.DATABASE_URL: str = os.getenv("DATABASE_URL")
        if not self.DATABASE_URL:
            raise ValueError("DATABASE_URL is required but missing in .env")

        # CORS_ORIGINS : string "a,b,c" → liste ["a", "b", "c"]
        cors_origins = os.getenv("CORS_ORIGINS")
        self.CORS_ORIGINS: List[str] = [
            origin.strip() for origin in cors_origins.split(",") if origin.strip()
        ]

# Instance unique à importer dans les autres modules
settings = Settings()