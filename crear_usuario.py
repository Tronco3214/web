import app
import db from app

with app.app_context():
    db.create_all()