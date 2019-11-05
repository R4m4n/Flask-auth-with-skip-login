# Copyright (c) * Raman
from app import db,app
import datetime
from flask_migrate import Migrate
import uuid
from sqlalchemy_utils.types import UUIDType
from sqlalchemy import UniqueConstraint



migrate = Migrate(app, db)


# This is a model class for the users table containing required data for a user.
class Users(db.Model):
    id = db.Column(UUIDType, primary_key=True,default = uuid.uuid4)
    name = db.Column(db.String(100), nullable = False)
    gender = db.Column(db.Enum('Male', 'Female'), nullable = False)
    email = db.Column(db.String(100), unique = True)
    password = db.Column(db.String(150), nullable = False)
    created_at = db.Column(db.DateTime,default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime,default=datetime.datetime.utcnow)
    status = db.Column(db.Boolean,default = False)
    association = db.relationship('Events',secondary=organiser_event_association_table, backref = db.backref('organiserEvent', lazy = 'dynamic'))

# This model class is for the table for the devices a user logs in with. 
class Devices(db.Model):
    id = db.Column(UUIDType, primary_key=True,default = uuid.uuid4)
    user_id = db.Column(UUIDType)
    created_at = db.Column(db.DateTime,default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime,default=datetime.datetime.utcnow)
    device_token = db.Column(db.Text)
    notifications = db.Column(db.Boolean, default = True)
    device_type = db.Column(db.String(30))
    status = db.Column(db.Boolean,default = True)
   

db.create_all()