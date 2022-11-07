from project import db
from flask_login import UserMixin


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # primary keys are required by SQLAlchemy
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    street_address = db.Column(db.String(100))
    city = db.Column(db.String(100))
    state = db.Column(db.String(2))
    country = db.Column(db.String(3))
    zip = db.Column(db.Integer)
    email = db.Column(db.String(100), unique=True)
    account_password = db.Column(db.String(255))
    account_type = db.Column(db.String(100))  # TODO Needs to be improved
    verified_email = db.Column(db.Boolean, default=False)
    verified_account = db.Column(db.Boolean, default=True)
    admin_account = db.Column(db.Boolean, default=False)
    security_code = db.Column(db.Integer, unique=True)


class Events(db.Model):
    eventID = db.Column(db.Integer, primary_key=True, autoincrement=True)  # primary keys are required by SQLAlchemy
    event_name = db.Column(db.String(100))
    town = db.Column(db.String(100))
    state = db.Column(db.String(100))
    country = db.Column(db.String(100))
    zipcode = db.Column(db.Integer)
    severity_level = db.Column(db.String(100))


class Items(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # primary keys are required by SQLAlchemy
    itemName = db.Column(db.String(45))
    category = db.Column(db.String(45))


class Requests(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # primary keys are required by SQLAlchemy
    eventID = db.Integer  # db.column(db.Integer(), db.ForeignKey("events.eventID"))
    itemQuantityID = db.Integer  # db.column(db.Integer(), db.ForeignKey("items.id"))
