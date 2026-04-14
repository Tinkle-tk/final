import os


class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL',
        'mysql+pymysql://root:root@localhost:3306/ics_vuln_kb?charset=utf8mb4',
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JSON_SORT_KEYS = False

    EXTRACTOR_MODE = os.getenv('EXTRACTOR_MODE', 'hybrid')
    LLM_MODEL = os.getenv('LLM_MODEL', 'gpt-4.1-mini')
    LLM_BASE_URL = os.getenv('LLM_BASE_URL')
    LLM_API_KEY = os.getenv('LLM_API_KEY')
