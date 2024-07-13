# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from datetime import datetime

from werkzeug.security import generate_password_hash, check_password_hash
from . import mongo
from bson import ObjectId


class Users:
    collection = mongo.db.users

    def __init__(self, username, email, password=None, date_joined=None, _id=None):
        self._id = _id if _id else ObjectId()
        self.username = username
        self.email = email
        self.password = password
        self.date_joined = date_joined if date_joined else datetime.utcnow()

    def save(self):
        user_data = {
            "username": self.username,
            "email": self.email,
            "password": self.password,
            "date_joined": self.date_joined
        }
        Users.collection.insert_one(user_data)

    def set_password(self, password):
        self.password = generate_password_hash(password)
        Users.collection.update_one({"username": self.username}, {"$set": {"password": self.password}})

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def update_email(self, new_email):
        self.email = new_email
        Users.collection.update_one({"username": self.username}, {"$set": {"email": new_email}})

    def update_username(self, new_username):
        self.username = new_username
        Users.collection.update_one({"username": self.username}, {"$set": {"username": new_username}})

    @classmethod
    def get_by_id(cls, user_id):
        user_data = cls.collection.find_one({"_id": user_id})
        if user_data:
            return cls(**user_data)

    @classmethod
    def get_by_email(cls, email):
        user_data = cls.collection.find_one({"email": email})
        if user_data:
            return cls(**user_data)

    @classmethod
    def get_by_username(cls, username):
        user_data = cls.collection.find_one({"username": username})
        if user_data:
            return cls(**user_data)

    def to_dict(self):
        return {
            "username": self.username,
            "email": self.email,
            "date_joined": self.date_joined.isoformat()
        }

    def to_json(self):
        user_dict = self.to_dict()
        user_dict["_id"] = str(self._id)
        return user_dict
