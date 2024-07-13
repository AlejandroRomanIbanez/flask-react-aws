# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from datetime import datetime, timedelta
from functools import wraps

from flask import request, jsonify
from flask_restx import Api, Resource, fields
from . import mongo
from .models import Users
from .config import BaseConfig
import requests
import boto3
import os
from dotenv import load_dotenv

load_dotenv()
COGNITO_APP_CLIENT_ID = os.getenv("COGNITO_APP_CLIENT_ID")
COGNITO_REGION = os.getenv("COGNITO_REGION")

cognito_client = boto3.client("cognito-idp", region_name=COGNITO_REGION)


rest_api = Api(version="1.0", title="Users API")


signup_model = rest_api.model('SignUpModel', {
    "username": fields.String(required=True, min_length=2, max_length=32),
    "email": fields.String(required=True, min_length=4, max_length=64),
    "password": fields.String(required=True, min_length=4, max_length=16)
})

login_model = rest_api.model('LoginModel', {
    "email": fields.String(required=True, min_length=4, max_length=64),
    "password": fields.String(required=True, min_length=4, max_length=16)
})

user_edit_model = rest_api.model('UserEditModel', {
    "userID": fields.String(required=True, min_length=1, max_length=32),
    "username": fields.String(required=True, min_length=2, max_length=32),
    "email": fields.String(required=True, min_length=4, max_length=64)
})


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers["authorization"]
        token = token.replace("Bearer ", "").strip()
        if not token:
            return {"success": False, "msg": "Valid JWT token is missing"}, 400

        try:
            user_info = cognito_client.get_user(AccessToken=token)
            current_user_email = None

            for attribute in user_info['UserAttributes']:
                if attribute['Name'] == 'email':
                    current_user_email = attribute['Value']
                    break
            if not current_user_email:
                return {"success": False, "msg": "User not found"}, 400,

            current_user = Users.get_by_email(current_user_email)
            if not current_user:
                return {"success": False, "msg": "User not found in database"}, 400

        except cognito_client.exceptions.NotAuthorizedException:
            return {"success": False, "msg": "Token is invalid or expired"}, 400

        return f(current_user, *args, **kwargs)
    return decorator


@rest_api.route('/api/users/register')
class Register(Resource):
    """
       Creates a new user by taking 'signup_model' input
    """
    @rest_api.expect(signup_model, validate=True)
    def post(self):
        req_data = request.get_json()

        _username = req_data.get("username")
        _email = req_data.get("email")
        _password = req_data.get("password")

        user_exists = mongo.db.users.find_one({"email": _email})
        if user_exists:
            return {"success": False, "msg": "Email already taken"}, 400
        try:
            cognito_client.sign_up(
                ClientId=COGNITO_APP_CLIENT_ID,
                Username=_username,
                Password=_password,
                UserAttributes=[
                    {'Name': 'email', 'Value': _email}
                ]
            )
            new_user = Users(username=_username, email=_email)
            new_user.set_password(_password)
            new_user.save()
            return {"success": True, "msg": "User registered successfully"}, 200

        except Exception as e:
            return {"success": False, "msg": str(e)}, 500


@rest_api.route('/api/users/login')
class Login(Resource):
    """
       Login user by taking 'login_model' input and return JWT token
    """

    @rest_api.expect(login_model, validate=True)
    def post(self):
        req_data = request.get_json()

        _email = req_data.get("email")
        _password = req_data.get("password")

        user_exists = mongo.db.users.find_one({"email": _email})

        if not user_exists:
            return {"success": False, "msg": "This email does not exist."}, 400

        try:
            response = cognito_client.initiate_auth(
                ClientId=COGNITO_APP_CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': user_exists['username'],
                    'PASSWORD': _password
                }
            )
            token = response['AuthenticationResult']['AccessToken']
            user = Users(**user_exists)
            return {"success": True, "token": token, "user": user.to_json()}, 200
        except cognito_client.exceptions.NotAuthorizedException:
            return {"success": False, "msg": "Wrong credentials."}, 400
        except Exception as e:
            return {"success": False, "msg": str(e)}, 500


@rest_api.route('/api/users/logout')
class LogoutUser(Resource):
    @token_required
    def post(self, current_user):
        try:
            token = request.headers.get("Authorization")
            if not token:
                return {"success": False, "msg": "Authorization header is missing"}, 401

            token = token.replace("Bearer ", "").strip()
            if not token:
                return {"success": False, "msg": "Valid JWT token is missing"}, 400

            cognito_client.global_sign_out(AccessToken=token)
            return {"success": True, "msg": "Logged out successfully"}, 200

        except cognito_client.exceptions.InvalidParameterException as e:
            return {"success": False, "msg": f"An error occurred: {str(e)}"}, 400
        except Exception as e:
            return {"success": False, "msg": f"An error occurred: {str(e)}"}, 500