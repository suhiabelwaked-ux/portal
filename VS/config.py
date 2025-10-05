import os

class Config:
    SECRET_KEY = os.urandom(24)
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    OUTPUT_FOLDER = os.path.join(os.getcwd(), 'output')
    TEMP_DATA_FOLDER = os.path.join(os.getcwd(), 'temp_data')
    
    # MySQL database configuration
    MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
    MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'admin_2025')
    MYSQL_DATABASE = os.environ.get('MYSQL_DATABASE', 'vulnerability_assessment')
    MYSQL_PORT = os.environ.get('MYSQL_PORT', '3306')
    
    # SQLAlchemy MySQL connection string
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DATABASE}'
    
    # Legacy DB config for backwards compatibility
    DB_CONFIG = {
        'user': MYSQL_USER,
        'password': MYSQL_PASSWORD,
        'host': MYSQL_HOST,
        'database': MYSQL_DATABASE,
        'port': MYSQL_PORT
    }