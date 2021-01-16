from flask import Flask
from flask_sqlalchemy import SQLAlchemy

  
app = Flask(__name__) 
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://root:root@localhost:3306/usersdb'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'

    id_user = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), unique=True, nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __repr__(self):
        return '<User %r>' % self.username

class Account(db.Model):
    __tablename__ = 'accounts'

    id_account = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=False, nullable=False)
    service = db.Column(db.String(80), unique=False, nullable=False)
    password = db.Column(db.String(80), nullable = False)

    def __init__(self, username, service, password):
        self.username = username
        self.service = service
        self.password = password
    
    def __repr__(self):
        return '<Account %r>' % self.service
