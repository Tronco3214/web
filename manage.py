from flask import Flask
from flask_migrate import Migrate, MigrateCommand
from app import app, db


migrate = Migrate(app, db)

if __name__ == '__main__':
    app.run(debug=True)


