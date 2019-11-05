# Copyright (c) * Raman
from flask import Flask
from response import Errors
from config import Config
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__, static_folder='../assets')
app.config.from_object(Config)
db = SQLAlchemy(app) # Creating SQL Alchemy object to be used in all over the app.

# Importing all routes.
from app import models
from app.users import bp as users_bp
