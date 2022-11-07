from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from project import dbCreds
import pymysql
from flask_login import LoginManager
from project.models import User

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

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    def load_user(user_id):
        return User.query.get(int(user_id))

    # blueprint for auth routes in our app
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app