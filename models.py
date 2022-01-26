from flask_login import UserMixin
from . import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    salt = db.Column(db.String(50))

class Shared_passwords(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    idFrom = db.Column(db.Integer)
    idTo = db.Column(db.Integer)

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.Integer)
    name = db.Column(db.String(1000))
    password = db.Column(db.String(1000))

class Recovery_code(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.Integer)
    code = db.Column(db.String(20))
    validThrough = db.Column(db.String(19))