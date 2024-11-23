import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'tu_clave_secreta_segura'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'mysql+pymysql://usuario:contraseña@localhost/encuestas_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = True