from flask_sqlalchemy import SQLAlchemy
from uuid import uuid4
from sqlalchemy.dialects.mysql import DECIMAL

db = SQLAlchemy()

def get_uuid():
    return uuid4().hex

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    fullname = db.Column(db.String(200), nullable = False)
    email = db.Column(db.String(50), unique = True, nullable = False)
    phone = db.Column(db.String(20), nullable = False)
    password = db.Column(db.String(200), nullable = False)
    location = db.Column(db.String(150), nullable = True)
    profile = db.relationship('Profile', uselist = False, back_populates='user')
    is_blocked = db.Column(db.Boolean, default=False)

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
    image = db.Column(db.String(200), nullable = True)
    user = db.relationship('User', back_populates='profile')

class Temp_user(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    fullname = db.Column(db.String(200), nullable = False)
    email = db.Column(db.String(50), unique = True, nullable = False)
    phone = db.Column(db.String(20), nullable = False)
    password = db.Column(db.String(200), nullable = False)
    otp = db.Column(db.String(10),nullable = False)

class Driver(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    fullname = db.Column(db.String(200), nullable = False)
    email = db.Column(db.String(50), unique = False, nullable = False)
    phone = db.Column(db.String(20), nullable = False)
    password = db.Column(db.String(200), nullable = False)
    is_verified = db.Column(db.Boolean, default = False)
    latitude = db.Column(db.String(200), nullable = True)
    longitude = db.Column(db.String(200), nullable = True)
    status = db.Column(db.String(200), default = 'inactive')
    KYC_verified = db.Column(db.Boolean, default = False)
    driver_verification = db.relationship('Driver_verification', back_populates='driver', uselist=False)
    vehicle_details = db.relationship('Vehicle_details', back_populates='driver')

class Driver_verification(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    license = db.Column(db.String(200), nullable=False)
    aadhar = db.Column(db.String(200), nullable=False)
    pan_card = db.Column(db.String(200), nullable=False)
    profile_pic = db.Column(db.String(200), nullable=True)
    driver_id = db.Column(db.Integer, db.ForeignKey('driver.id'), nullable=False)
    driver = db.relationship('Driver', back_populates='driver_verification')

class Vehicle_type(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    type = db.Column(db.String(50), nullable = False)
    base_price = db.Column(DECIMAL(10,2),nullable = False)
    base_distance_KM = db.Column(db.Integer, nullable = False)
    price_per_km = db.Column(DECIMAL(10,2), nullable = False)
    Image = db.Column(db.String(100), nullable = True)
    vehicle_details = db.relationship('Vehicle_details', back_populates='vehicle_type')

class Vehicle_details(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    make = db.Column(db.Integer, nullable = True)
    model = db.Column(db.String(50), nullable = True)
    RC = db.Column(db.String(100), nullable = True)
    license_plate = db.Column(db.String(100), nullable = True)
    insurance = db.Column(db.String(100), nullable = True)
    vehicle_type_id = db.Column(db.Integer, db.ForeignKey('vehicle_type.id'), nullable=True)  
    driver_id = db.Column(db.Integer, db.ForeignKey('driver.id'), nullable=False)  
    vehicle_type = db.relationship('Vehicle_type', back_populates='vehicle_details')
    driver = db.relationship('Driver', back_populates='vehicle_details')

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    fullname = db.Column(db.String(200), nullable = False)
    email = db.Column(db.String(50), unique = True, nullable = False)
    phone = db.Column(db.String(20), nullable = False)
    password = db.Column(db.String(200), nullable = False)
