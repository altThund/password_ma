from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import  CSRFProtect
import os
  
app = Flask(__name__) 
app.secret_key = 'bittersweet'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
csrf = CSRFProtect(app)

class User(db.Model):
    __tablename__ = 'users'

    id_user = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), unique=False, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)

    def __init__(self, username, password, email):
        self.username = username
        self.password = password
        self.email = email

    def is_authenticated(self):
        return True  

    def is_active(self):
        return True

    def get_id(self):
        return self.id_user

    def __repr__(self):
        return '<User %r>' % self.username

class Account(db.Model):
    __tablename__ = 'accounts'

    id_account = db.Column(db.Integer, primary_key=True)
    id_user = db.Column(db.Integer, unique=False, nullable=False)
    service = db.Column(db.String(80), unique=False, nullable=False)
    password = db.Column(db.String(80), nullable = False)

    def __init__(self, id_user, service, password):
        self.id_user = id_user
        self.service = service
        self.password = password
    
    def __repr__(self):
        return '<Account %r>' % self.service
