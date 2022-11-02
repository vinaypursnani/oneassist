from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from project import dbCreds
import pymysql

pymysql.install_as_MySQLdb()

# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()


def create_app():
    app = Flask(__name__)
    app.debug = True

    app.config['SECRET_KEY'] = 'AF598AA9BD88A822'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config[
        'SQLALCHEMY_DATABASE_URI'] = f'mysql://{dbCreds.user}:{dbCreds.password}@{dbCreds.host}/{dbCreds.database}'

    db.init_app(app)

    # blueprint for auth routes in our app
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
