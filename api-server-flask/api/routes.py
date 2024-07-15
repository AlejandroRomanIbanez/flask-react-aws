# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from functools import wraps

import requests
from flask import request, redirect
from flask_restx import Api, Resource, fields
from . import mongo
from .models import Users
import boto3
from dotenv import load_dotenv
from .config import BaseConfig

load_dotenv()
COGNITO_APP_CLIENT_ID = BaseConfig.COGNITO_APP_CLIENT_ID
COGNITO_REGION = BaseConfig.COGNITO_REGION
COGNITO_DOMAIN = BaseConfig.COGNITO_DOMAIN
COGNITO_REDIRECT_URI = BaseConfig.COGNITO_REDIRECT_URI
GOOGLE_CLIENT_ID = BaseConfig.GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET = BaseConfig.GOOGLE_CLIENT_SECRET

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


@rest_api.route('/api/users/google-login')
class GoogleLogin(Resource):
    def get(self):
        redirect_uri = (
            f"https://{COGNITO_DOMAIN}/oauth2/authorize"
            f"?response_type=code&client_id={COGNITO_APP_CLIENT_ID}&redirect_uri={COGNITO_REDIRECT_URI}"
            f"&identity_provider=Google&scope=email+openid+profile"
        )
        return redirect(redirect_uri)


@rest_api.route('/api/users/callback')
class Callback(Resource):
    def get(self):
        code = request.args.get('code')
        if not code:
            return {"success": False, "msg": "Code not provided"}, 400

        try:
            # Exchange the authorization code for tokens
            token_url = f"https://{COGNITO_DOMAIN}/oauth2/token"
            token_data = {
                'grant_type': 'authorization_code',
                'client_id': COGNITO_APP_CLIENT_ID,
                'code': code,
                'redirect_uri': COGNITO_REDIRECT_URI,
            }
            token_headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            token_response = requests.post(token_url, data=token_data, headers=token_headers)
            token_json = token_response.json()

            if 'error' in token_json:
                return {"success": False, "msg": token_json['error']}, 400

            access_token = token_json['access_token']
            id_token = token_json['id_token']

            # Get user info from the access token
            user_info_url = f"https://{COGNITO_DOMAIN}/oauth2/userInfo"
            user_info_response = requests.get(user_info_url, headers={'Authorization': f'Bearer {access_token}'})
            user_info = user_info_response.json()

            email = user_info.get('email')

            if not email:
                return {"success": False, "msg": "Email not found in user info"}, 400

            user_exists = mongo.db.users.find_one({"email": email})
            if not user_exists:
                # Create a new user if not found in the database
                new_user = Users(username=user_info.get('username'), email=email)
                new_user.save()

                # Log the creation of a new user
                print(f"New user created: {email}")

            else:
                # Log the existing user information
                print(f"Existing user found: {email}")

            user = Users(**user_exists) if user_exists else new_user
            return {"success": True, "token": access_token, "id_token": id_token, "user": user.to_json()}, 200
        except Exception as e:
            return {"success": False, "msg": str(e)}, 500
