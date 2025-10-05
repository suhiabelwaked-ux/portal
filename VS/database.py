import os
import pymysql

def get_db_connection():
    """Establishes and returns a connection to the MySQL database."""
    try:
        # MySQL connection settings
        mysql_config = {
            'host': os.environ.get('MYSQL_HOST', 'localhost'),
            'port': int(os.environ.get('MYSQL_PORT', 3306)),
            'user': os.environ.get('MYSQL_USER', 'root'),
            'password': os.environ.get('MYSQL_PASSWORD', 'admin_2025'),
            'database': os.environ.get('MYSQL_DATABASE', 'vulnerability_assessment'),
            'charset': 'utf8mb4',
            'autocommit': True,
            'cursorclass': pymysql.cursors.DictCursor
        }
        
        conn = pymysql.connect(**mysql_config)
        return conn
        
    except pymysql.Error as err:
        print(f"Error connecting to MySQL: {err}")
        return None